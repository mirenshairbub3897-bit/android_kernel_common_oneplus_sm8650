#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/pid.h> // Added for pid_task and find_vpid

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BGMI Dev");
MODULE_DESCRIPTION("Offset Validator for BGMI (libUE4.so relative) - Android");

// ========== RELATIVE OFFSETS (to libUE4.so base) ==========
// Note: These offsets are often game version specific and may need updates.
#define OFFSET_GWORLD                   0xe4f28c0
#define OFFSET_VMATRIX                  0xe4c9ff0
#define OFFSET_GNAME                    0xdf74800
#define OFFSET_GUOBJECT                 0xe22f8d0
#define OFFSET_PROJECT_WORLD_TO_SCREEN  0xa7212f4
#define OFFSET_WAS_AVATAR_RECENTLY_RENDERED 0x6b5cce8

// Class offsets
#define OFFSET_LAST_SUBMIT_TIME            0x484
#define OFFSET_LAST_RENDER_TIME            0x488
#define OFFSET_LAST_RENDER_TIME_ON_SCREEN  0x48c
#define OFFSET_SHADOW_LAST_RENDER_TIME     0x490

#define OFFSET_ROOT_COMPONENT              0x208
#define OFFSET_PERSISTENT_LEVEL            0x30
#define OFFSET_PLAYER_CONTROLLER           0x30
#define OFFSET_ACKNOWLEDGED_PAWN           0x528
#define OFFSET_MESH                        0x510

#define OFFSET_POSITION                    0x1e4
#define OFFSET_CAMERA_CACHE                0x520
#define OFFSET_POINTER_POV                 0x10

#define OFFSET_HEALTH                      0xe60
#define OFFSET_TEAM_ID                     0x998
#define OFFSET_PLAYER_NAME                 0x960
#define OFFSET_PLAYER_UID                  0x988
#define OFFSET_NATION                      0x970
#define OFFSET_B_DEAD                      0xe7c
#define OFFSET_B_IS_AI                     0xa59

#define OFFSET_CACHED_BONE_SPACE_TRANSFORMS      0xc40
#define OFFSET_CACHED_COMPONENT_SPACE_TRANSFORMS 0xc50

#define OFFSET_UWORLD_OWNING_GAMEINSTANCE  0x1B8
#define OFFSET_GAMEINSTANCE_LOCALPLAYERS   0x38
#define OFFSET_LOCALPLAYER_PLAYERCONTROLLER 0x30

#define ACTORS_ARRAY_OFFSET                0xA0 // Usually points to the array of actors

static int target_pid = -1; // Renamed to avoid conflict with global 'pid'
module_param(target_pid, int, 0644);

// Check if a process is potentially the target BGMI process
static bool is_bgmi_process(struct task_struct *task) {
    // Android process names can have variations.
    // We'll check for common patterns.
    // 1. Exact match for the main process.
    // 2. Partial match, as the name might be truncated or have suffixes.
    
    // Check for "com.pubg.imobile:plugin" which is common
    if (task->comm && strncmp(task->comm, "com.pubg.imobile:plugin", 23) == 0) {
        pr_info("[BGMI] Found BGMI process (variant): '%s' (PID: %d)\n", task->comm, task->pid);
        return true;
    }
    
    // Check for the main process "com.pubg.imobile" (though less likely to be the only one)
    if (task->comm && strcmp(task->comm, "com.pubg.imobile") == 0) {
        pr_info("[BGMI] Found BGMI process (main): '%s' (PID: %d)\n", task->comm, task->pid);
        return true;
    }

    // Add more checks if needed for other BGMI variants or specific Android versions.
    // For debugging, you can uncomment this to see all process names:
    // pr_info("[BGMI] Debug Process: %s (PID: %d)\n", task->comm, task->pid);

    return false;
}

// Safe read using access_process_vm
static int read_remote_memory(struct task_struct *task, unsigned long addr, void *buf, size_t len) {
    int ret;
    if (!task || !buf || len == 0 || addr == 0) // Added addr == 0 check
        return -EINVAL;

    // Ensure the address is within a plausible user-space range for Android.
    // TASK_SIZE might be too restrictive on some Android versions or architectures.
    // A common range for user space starts from 0x10000 and goes up to a high address.
    // For safety, you might want to add a check against a max user space address if known.
    // For now, we rely on access_process_vm failing for invalid addresses.

    ret = access_process_vm(task, addr, buf, len, FOLL_FORCE);
    if (ret == len) {
        return 0; // Success
    } else if (ret >= 0) {
        pr_warn("[BGMI] read_remote_memory: Partial read for 0x%lx, got %d/%zu bytes. PID: %d\n", addr, ret, len, task->pid);
        return -EFAULT; // Indicate a partial read or error
    } else {
        pr_err("[BGMI] read_remote_memory: access_process_vm failed for 0x%lx with error %d. PID: %d\n", addr, ret, task->pid);
        return ret; // Propagate the error code
    }
}

// Correctly reads /proc/pid/maps to find library base address
static unsigned long get_lib_base(struct task_struct *task, const char *lib_name) {
    struct file *maps_file;
    char *buf = NULL;
    char path[64];
    unsigned long base = 0;
    loff_t pos = 0;
    ssize_t len;
    char *line_start, *line_end; // Use line_start and line_end for strsep

    if (!task || !lib_name)
        return 0;

    snprintf(path, sizeof(path), "/proc/%d/maps", task->pid);
    maps_file = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(maps_file)) {
        pr_err("[BGMI] Failed to open %s (PID: %d). Error: %ld\n", path, task->pid, PTR_ERR(maps_file));
        return 0;
    }

    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf) {
        pr_err("[BGMI] Failed to allocate memory for maps buffer.\n");
        filp_close(maps_file, NULL);
        return 0;
    }

    while ((len = kernel_read(maps_file, buf, 4095, &pos)) > 0) {
        buf[len] = '\0'; // Ensure null termination
        line_start = buf;
        
        while ((line_end = strsep(&line_start, "\n")) != NULL) {
            if (!*line_end) continue; // Skip empty lines

            // Check if the library name is present in the current line
            if (strstr(line_end, lib_name) != NULL) {
                char *address_end;
                // The base address is the first field, which is hexadecimal
                base = simple_strtoul(line_end, &address_end, 16);
                
                // Ensure the base address seems valid (not 0, and is at the beginning of the line)
                if (base > 0 && address_end == line_end + 16) { // Common format: "addr-addr perm offset file"
                    pr_info("[BGMI] Found %s base for PID %d: 0x%lx\n", lib_name, task->pid, base);
                    kfree(buf);
                    filp_close(maps_file, NULL);
                    return base;
                }
            }
        }
    }

    if (len < 0)
        pr_err("[BGMI] Error reading %s (PID: %d): %zd\n", path, task->pid, len);
    else
        pr_info("[BGMI] Reached end of %s (PID: %d) without finding %s\n", path, task->pid, lib_name);

    kfree(buf);
    filp_close(maps_file, NULL);
    return 0;
}

// Helper to print values
static void print_val(const char *desc, unsigned long val) {
    pr_info("[BGMI] %s: 0x%lx\n", desc, val);
}

// Helper to print integers
static void print_int(const char *desc, int val) {
    pr_info("[BGMI] %s: %d\n", desc, val);
}

// ==== Main module initialization ====
static int __init bgmi_checker_init(void) {
    struct task_struct *task = NULL;
    unsigned long libue4_base = 0;
    unsigned long gworld = 0, persistent_level = 0, actors_data = 0, actor_count = 0;
    unsigned long first_actor = 0, mesh = 0, root_comp = 0;
    float position[3] = {0.0f}; // Initialize to zero
    int health = 0;
    unsigned long team_id = 0;
    char name[32] = {0}; // Initialize to zeros
    int is_ai = 0;
    unsigned long local_pawn_team_id = 0;
    bool found_process = false;
    int debug_process_count = 0; // Counter for debug process listing

    pr_info("[BGMI] Module loaded. Searching for BGMI process...\n");

    // Iterate through all processes to find the BGMI one
    rcu_read_lock();
    for_each_process(task) {
        if (is_bgmi_process(task)) {
            target_pid = task->pid;
            found_process = true;
            // Found the process, now we can break our loop or continue if we want to verify or pick specific one.
            // For simplicity, we'll take the first one found by is_bgmi_process.
            break; 
        }
        
        // Debug: Show processes with "pubg" in name (limited to 5) for troubleshooting
        if (task->comm && strstr(task->comm, "pubg") != NULL && debug_process_count < 5) {
            pr_info("[BGMI] Debug: Process with 'pubg' -> '%s' (PID: %d)\n", 
                   task->comm, task->pid);
            debug_process_count++;
        }
    }
    rcu_read_unlock();

    if (!found_process) {
        pr_err("[BGMI] Target BGMI process ('com.pubg.imobile' or variant) NOT FOUND!\n");
        pr_err("[BGMI] Please ensure BGMI is running before loading the module.\n");
        pr_err("[BGMI] Check dmesg output for 'Debug: Process with 'pubg'' to see running PUBG-related processes.\n");
        pr_err("[BGMI] Tip: Use 'adb shell ps -A | grep pubg' to verify process names.\n");
        return -ENOENT; // No such process
    }
    pr_info("[BGMI] Found BGMI process with PID = %d\n", target_pid);

    // Get the task_struct for the found PID
    task = pid_task(find_vpid(target_pid), PIDTYPE_PID);
    if (!task) {
        pr_err("[BGMI] Could not get task_struct for PID %d.\n", target_pid);
        return -ESRCH; // No such process
    }

    // Find the base address of libUE4.so
    libue4_base = get_lib_base(task, "libUE4.so");
    if (libue4_base == 0) {
        pr_err("[BGMI] Could not find base address of 'libUE4.so' in process maps for PID %d.\n", target_pid);
        pr_err("[BGMI] Ensure BGMI is running properly and libUE4.so is loaded.\n");
        return -EINVAL;
    }
    pr_info("[BGMI] libUE4.so base address found: 0x%lx\n", libue4_base);

    // Calculate absolute addresses
    unsigned long abs_gworld = libue4_base + OFFSET_GWORLD;
    unsigned long abs_vmatrix = libue4_base + OFFSET_VMATRIX;
    unsigned long abs_w2s_func = libue4_base + OFFSET_PROJECT_WORLD_TO_SCREEN;

    pr_info("[BGMI] --- Attempting to read critical game data for PID %d --- \n", target_pid);

    // --- Read GWorld ---
    if (read_remote_memory(task, abs_gworld, &gworld, sizeof(gworld))) {
        pr_err("[BGMI] FAILED to read GWorld at 0x%lx\n", abs_gworld);
    } else {
        print_val("GWorld", gworld);
        // Basic validation for GWorld
        if (gworld == 0 || gworld > 0x7fffffffffff) { // Assuming user-space addresses are within this range
            pr_warn("[BGMI] GWorld value (0x%lx) seems potentially invalid. Data access might fail.\n", gworld);
        }
    }

    // If GWorld is valid, try to access further data
    if (gworld != 0) {
        // --- Accessing Actors Data ---
        // Read PersistentLevel first
        if (read_remote_memory(task, gworld + OFFSET_PERSISTENT_LEVEL, &persistent_level, sizeof(persistent_level))) {
            pr_err("[BGMI] FAILED to read PersistentLevel from GWorld (offset 0x%x)\n", OFFSET_PERSISTENT_LEVEL);
        } else {
            print_val("PersistentLevel", persistent_level);
            if (persistent_level != 0) {
                // Need to read actor count and then the actor array pointer.
                // The array pointer is often preceded by the count.
                unsigned long actors_array_ptr_addr = persistent_level + ACTORS_ARRAY_OFFSET;
                unsigned long actor_count_addr = actors_array_ptr_addr - sizeof(unsigned long); // Assuming count is just before the array

                // Read Actor Count
                if (read_remote_memory(task, actor_count_addr, &actor_count, sizeof(actor_count))) {
                    pr_err("[BGMI] FAILED to read Actor count from PersistentLevel (offset 0x%lx)\n", actor_count_addr);
                } else {
                    // Actor count can be large, cast to int for printing if it's within int range, but consider it unsigned long
                    print_val("Actor Count", actor_count);
                    if (actor_count > 10000) { // Heuristic check for very large numbers that might indicate an error
                         pr_warn("[BGMI] Actor count (%lu) seems unusually high, potential issue.\n", actor_count);
                    }
                }

                // Read Actors Data Pointer (start of the array)
                if (read_remote_memory(task, actors_array_ptr_addr, &actors_data, sizeof(actors_data))) {
                    pr_err("[BGMI] FAILED to read Actors data pointer from PersistentLevel (offset 0x%x)\n", ACTORS_ARRAY_OFFSET);
                } else {
                    print_val("Actors data pointer", actors_data);
                    if (actor_count > 0 && actor_count < 10000 && actors_data != 0) { // Proceed if count is reasonable and pointer valid
                        
                        // Read the first actor address from the array
                        if (read_remote_memory(task, actors_data, &first_actor, sizeof(first_actor))) {
                            pr_err("[BGMI] FAILED to read first actor's address from Actors array (offset 0x%lx)\n", actors_data);
                        } else {
                            print_val("First Actor address", first_actor);
                            if (first_actor != 0) {
                                // --- Accessing Data of the First Actor ---
                                // Read Mesh pointer
                                if (read_remote_memory(task, first_actor + OFFSET_MESH, &mesh, sizeof(mesh))) {
                                    pr_err("[BGMI] FAILED: Read Mesh pointer from Actor (offset 0x%x)\n", OFFSET_MESH);
                                } else {
                                    print_val("Mesh pointer", mesh);
                                    if (mesh != 0) {
                                        // Read Last Render Time from Mesh (example data)
                                        unsigned long lrt;
                                        if (read_remote_memory(task, mesh + OFFSET_LAST_RENDER_TIME, &lrt, sizeof(lrt))) {
                                            pr_err("[BGMI] FAILED: Read LastRenderTime from Mesh (offset 0x%x)\n", OFFSET_LAST_RENDER_TIME);
                                        } else {
                                            print_val("LastRenderTime", lrt);
                                        }
                                    }
                                }

                                // Read Root Component pointer
                                if (read_remote_memory(task, first_actor + OFFSET_ROOT_COMPONENT, &root_comp, sizeof(root_comp))) {
                                    pr_err("[BGMI] FAILED: Read RootComponent pointer from Actor (offset 0x%x)\n", OFFSET_ROOT_COMPONENT);
                                } else {
                                    print_val("RootComponent pointer", root_comp);
                                    if (root_comp != 0) {
                                        // Read Position from Root Component
                                        if (read_remote_memory(task, root_comp + OFFSET_POSITION, position, sizeof(position))) {
                                            pr_err("[BGMI] FAILED: Read Position from RootComponent (offset 0x%x)\n", OFFSET_POSITION);
                                        } else {
                                            pr_info("[BGMI] Position (X, Y, Z): %.2f, %.2f, %.2f\n", position[0], position[1], position[2]);
                                            // Additional check for position: if all are zero, it might be an invalid component
                                            if (position[0] == 0.0f && position[1] == 0.0f && position[2] == 0.0f) {
                                                pr_warn("[BGMI] Actor position is all zeros, may indicate an issue.\n");
                                            }
                                        }
                                    }
                                }

                                // Read Health
                                if (read_remote_memory(task, first_actor + OFFSET_HEALTH, &health, sizeof(health))) {
                                    pr_err("[BGMI] FAILED: Read Health from Actor (offset 0x%x)\n", OFFSET_HEALTH);
                                } else {
                                    print_int("Health", health);
                                }

                                // Read TeamID
                                if (read_remote_memory(task, first_actor + OFFSET_TEAM_ID, &team_id, sizeof(team_id))) {
                                    pr_err("[BGMI] FAILED: Read TeamID from Actor (offset 0x%x)\n", OFFSET_TEAM_ID);
                                } else {
                                    print_int("TeamID", (int)team_id);
                                }
                                
                                // Read Player Name
                                {
                                    unsigned long name_ptr;
                                    if (read_remote_memory(task, first_actor + OFFSET_PLAYER_NAME, &name_ptr, sizeof(name_ptr))) {
                                        pr_err("[BGMI] FAILED: Read PlayerName pointer from Actor (offset 0x%x)\n", OFFSET_PLAYER_NAME);
                                    } else if (name_ptr != 0) {
                                        if (read_remote_memory(task, name_ptr, name, sizeof(name) - 1)) { // Read up to 31 chars
                                            pr_err("[BGMI] FAILED: Read PlayerName data from pointer 0x%lx\n", name_ptr);
                                        } else {
                                            name[sizeof(name) - 1] = 0; // Ensure null termination
                                            pr_info("[BGMI] PlayerName: %s\n", name);
                                        }
                                    } else {
                                        pr_info("[BGMI] PlayerName pointer is null.\n");
                                    }
                                }

                                // Read bIsAI
                                if (read_remote_memory(task, first_actor + OFFSET_B_IS_AI, &is_ai, sizeof(is_ai))) {
                                    pr_err("[BGMI] FAILED: Read bIsAI from Actor (offset 0x%x)\n", OFFSET_B_IS_AI);
                                } else {
                                    pr_info("[BGMI] bIsAI: %s\n", is_ai ? "true (BOT)" : "false (Player)");
                                }
                            } else {
                                pr_warn("[BGMI] First actor address is zero. No actors found or error.\n");
                            }
                        }
                    } else {
                        pr_warn("[BGMI] Actor count (%lu) or Actors data pointer (0x%lx) appears invalid, skipping actor iteration.\n", actor_count, actors_data);
                    }
                }
            } else {
                pr_warn("[BGMI] PersistentLevel is zero. Can't access actors.\n");
            }
        }

        // --- Local Player Chain ---
        {
            unsigned long game_instance, local_players_array, local_player, player_controller, local_pawn;
            pr_info("[BGMI] --- Testing Local Player chain from GWorld (PID: %d) ---\n", target_pid);
            
            // Read OwningGameInstance
            if (read_remote_memory(task, gworld + OFFSET_UWORLD_OWNING_GAMEINSTANCE, &game_instance, sizeof(game_instance))) {
                pr_err("[BGMI] FAILED: Read OwningGameInstance from GWorld (offset 0x%x)\n", OFFSET_UWORLD_OWNING_GAMEINSTANCE);
            } else {
                print_val("GameInstance", game_instance);
                if (game_instance != 0) {
                    // Read LocalPlayers array pointer
                    if (read_remote_memory(task, game_instance + OFFSET_GAMEINSTANCE_LOCALPLAYERS, &local_players_array, sizeof(local_players_array))) {
                        pr_err("[BGMI] FAILED: Read LocalPlayers array from GameInstance (offset 0x%x)\n", OFFSET_GAMEINSTANCE_LOCALPLAYERS);
                    } else {
                        print_val("LocalPlayers Array", local_players_array);
                        if (local_players_array != 0) {
                            // Read the first LocalPlayer pointer
                            if (read_remote_memory(task, local_players_array, &local_player, sizeof(local_player))) {
                                pr_err("[BGMI] FAILED: Read LocalPlayer[0] from LocalPlayers array (offset 0x%lx)\n", local_players_array);
                            } else {
                                print_val("LocalPlayer[0]", local_player);
                                if (local_player != 0) {
                                    // Read PlayerController from LocalPlayer
                                    if (read_remote_memory(task, local_player + OFFSET_LOCALPLAYER_PLAYERCONTROLLER, &player_controller, sizeof(player_controller))) {
                                        pr_err("[BGMI] FAILED: Read PlayerController from LocalPlayer (offset 0x%x)\n", OFFSET_LOCALPLAYER_PLAYERCONTROLLER);
                                    } else {
                                        print_val("PlayerController", player_controller);
                                        if (player_controller != 0) {
                                            // Read AcknowledgedPawn (local player's pawn)
                                            if (read_remote_memory(task, player_controller + OFFSET_ACKNOWLEDGED_PAWN, &local_pawn, sizeof(local_pawn))) {
                                                pr_err("[BGMI] FAILED: Read AcknowledgedPawn from PlayerController (offset 0x%x)\n", OFFSET_ACKNOWLEDGED_PAWN);
                                            } else {
                                                print_val("Local Pawn", local_pawn);
                                                if (local_pawn != 0) {
                                                    // Read Local Player's TeamID
                                                    unsigned long ltid;
                                                    if (read_remote_memory(task, local_pawn + OFFSET_TEAM_ID, &ltid, sizeof(ltid))) {
                                                        pr_err("[BGMI] FAILED: Read Local TeamID from Local Pawn (offset 0x%x)\n", OFFSET_TEAM_ID);
                                                    } else {
                                                        local_pawn_team_id = ltid;
                                                        print_int("Local Pawn TeamID", (int)local_pawn_team_id);
                                                    }
                                                } else {
                                                    pr_info("[BGMI] Local Pawn is null. You might be in a menu or lobby.\n");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            pr_warn("[BGMI] LocalPlayers array pointer is zero. No local players found.\n");
                        }
                    }
                } else {
                    pr_warn("[BGMI] GameInstance is zero. Cannot access local players.\n");
                }
            }
        }
    } else {
        pr_err("[BGMI] GWorld is zero or invalid. Cannot proceed with data reading.\n");
    }

    // --- Test VMatrix and W2S function ---
    pr_info("[BGMI] --- Testing VMatrix and ProjectWorldToScreen function (PID: %d) ---\n", target_pid);
    {
        // VMatrix is typically 4x4, so 16 floats or 16 * 4 bytes = 64 bytes.
        // Storing as unsigned int array for raw hex output similar to original.
        unsigned int vmatrix[16]; 
        if (read_remote_memory(task, abs_vmatrix, vmatrix, sizeof(vmatrix))) {
            pr_err("[BGMI] FAILED to read VMatrix at 0x%lx\n", abs_vmatrix);
        } else {
            pr_info("[BGMI] VMatrix first 4 values: 0x%08x 0x%08x 0x%08x 0x%08x\n",
                   vmatrix[0], vmatrix[1], vmatrix[2], vmatrix[3]);
        }
    }
    {
        // Read a small chunk to check if the function pointer is valid
        unsigned char code[8]; 
        if (read_remote_memory(task, abs_w2s_func, code, sizeof(code))) {
            pr_err("[BGMI] FAILED to read code at ProjectWorldToScreen function address 0x%lx\n", abs_w2s_func);
        } else {
            pr_info("[BGMI] ProjectWorldToScreen first bytes: %02x %02x %02x %02x ...\n",
                   code[0], code[1], code[2], code[3]);
        }
    }

    pr_info("[BGMI] Offset check complete. Please review the entire dmesg output for details.\n");
    // The module is meant for checking offsets, so it doesn't need to keep running constantly.
    // A simple return 0 indicates module loaded successfully.
    return 0;
}

// ==== Module cleanup ====
static void __exit bgmi_checker_exit(void) {
    pr_info("[BGMI] Module unloaded.\n");
}

module_init(bgmi_checker_init);
module_exit(bgmi_checker_exit);
