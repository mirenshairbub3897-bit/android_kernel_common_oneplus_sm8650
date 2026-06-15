// bgmi_offset_checker.c (Fixed: access_process_vm, no use_mm/unuse_mm)
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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BGMI Dev");
MODULE_DESCRIPTION("Offset Validator for BGMI (libUE4.so relative)");

// ========== RELATIVE OFFSETS (to libUE4.so base) ==========
#define OFFSET_GWORLD                   0xe4f28c0
#define OFFSET_VMATRIX                  0xe4c9ff0
#define OFFSET_GNAME                    0xdf74800
#define OFFSET_GUOBJECT                 0xe22f8d0
#define OFFSET_PROJECT_WORLD_TO_SCREEN  0xa7212f4
#define OFFSET_WAS_AVATAR_RECENTLY_RENDERED 0x6b5cce8

// Class offsets (relative to object instance)
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

#define ACTORS_ARRAY_OFFSET                0xA0

static int pid = -1;
module_param(pid, int, 0644);

// Safe read using access_process_vm (exported, works on all kernels)
static int read_remote_memory(struct task_struct *task, unsigned long addr, void *buf, size_t len)
{
    int ret;
    if (!task || !buf || len == 0 || addr < TASK_SIZE)
        return -EINVAL;

    ret = access_process_vm(task, addr, buf, len, FOLL_FORCE);
    if (ret == len)
        return 0;
    return -EFAULT;
}

// Find base address of a library (e.g. "libUE4.so") using /proc/pid/maps
static unsigned long get_lib_base(struct task_struct *task, const char *lib_name)
{
    struct file *maps_file;
    char *buf = NULL;
    char path[64];
    unsigned long base = 0;
    loff_t pos = 0;
    int len;
    char *line, *p;

    if (!task || !lib_name)
        return 0;

    snprintf(path, sizeof(path), "/proc/%d/maps", task->pid);
    maps_file = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(maps_file)) {
        printk(KERN_ERR "[BGMI] Failed to open %s\n", path);
        return 0;
    }

    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf) {
        filp_close(maps_file, NULL);
        return 0;
    }

    while ((len = kernel_read(maps_file, buf, 4095, &pos)) > 0) {
        buf[len] = '\0';
        line = buf;
        while (line && *line) {
            p = strstr(line, lib_name);
            if (p) {
                char *end;
                base = simple_strtoul(line, &end, 16);
                if (base > 0) {
                    printk(KERN_INFO "[BGMI] Found %s base: 0x%lx\n", lib_name, base);
                    kfree(buf);
                    filp_close(maps_file, NULL);
                    return base;
                }
            }
            line = strchr(line, '\n');
            if (line) line++;
        }
        pos -= len;
    }
    kfree(buf);
    filp_close(maps_file, NULL);
    return 0;
}

static void print_val(const char *desc, unsigned long val) {
    printk(KERN_INFO "[BGMI] %s: 0x%lx\n", desc, val);
}
static void print_int(const char *desc, int val) {
    printk(KERN_INFO "[BGMI] %s: %d\n", desc, val);
}

static int __init bgmi_checker_init(void)
{
    struct task_struct *task;
    unsigned long libue4_base;
    unsigned long gworld, persistent_level, actors_data, actor_count;
    unsigned long first_actor, mesh, root_comp;
    float position[3];
    int health;
    unsigned long team_id;
    char name[32] = {0};
    int is_ai;
    unsigned long local_pawn_team_id = 0;

    printk(KERN_INFO "[BGMI] Module loaded – searching for BGMI process...\n");

    rcu_read_lock();
    for_each_process(task) {
        if (strcmp(task->comm, "com.pubg.imobi") == 0) {
            pid = task->pid;
            break;
        }
    }
    rcu_read_unlock();

    if (pid == -1) {
        printk(KERN_ERR "[BGMI] Process 'com.pubg.imobile' not found.\n");
        return -ENOENT;
    }
    printk(KERN_INFO "[BGMI] Found process PID = %d\n", pid);

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        printk(KERN_ERR "[BGMI] Could not get task_struct\n");
        return -ESRCH;
    }

    libue4_base = get_lib_base(task, "libUE4.so");
    if (libue4_base == 0) {
        printk(KERN_ERR "[BGMI] Could not find libUE4.so base in process maps.\n");
        return -EINVAL;
    }
    printk(KERN_INFO "[BGMI] libUE4.so base = 0x%lx\n", libue4_base);

    unsigned long abs_gworld = libue4_base + OFFSET_GWORLD;
    unsigned long abs_vmatrix = libue4_base + OFFSET_VMATRIX;
    unsigned long abs_w2s_func = libue4_base + OFFSET_PROJECT_WORLD_TO_SCREEN;

    printk(KERN_INFO "[BGMI] Testing absolute addresses...\n");
    print_val("Absolute GWorld", abs_gworld);

    if (read_remote_memory(task, abs_gworld, &gworld, sizeof(gworld))) {
        printk(KERN_ERR "[BGMI] FAILED to read GWorld\n");
        return -EFAULT;
    }
    print_val("GWorld value", gworld);
    if (gworld == 0 || gworld > 0x7fffffffffff) {
        printk(KERN_WARNING "[BGMI] GWorld looks invalid, but continuing...\n");
    }

    if (gworld != 0) {
        if (read_remote_memory(task, gworld + OFFSET_PERSISTENT_LEVEL, &persistent_level, sizeof(persistent_level))) {
            printk(KERN_ERR "[BGMI] FAILED to read PersistentLevel\n");
        } else {
            print_val("PersistentLevel", persistent_level);
            if (persistent_level != 0) {
                unsigned long count_addr = persistent_level + ACTORS_ARRAY_OFFSET - 0x8;
                if (read_remote_memory(task, count_addr, &actor_count, sizeof(actor_count))) {
                    printk(KERN_ERR "[BGMI] FAILED to read Actor count\n");
                } else {
                    print_int("Actor count", (int)actor_count);
                }
                if (read_remote_memory(task, persistent_level + ACTORS_ARRAY_OFFSET, &actors_data, sizeof(actors_data))) {
                    printk(KERN_ERR "[BGMI] FAILED to read Actors data pointer\n");
                } else {
                    print_val("Actors data pointer", actors_data);
                    if (actor_count > 0 && actor_count < 10000 && actors_data != 0) {
                        if (read_remote_memory(task, actors_data, &first_actor, sizeof(first_actor))) {
                            printk(KERN_ERR "[BGMI] FAILED to read first actor\n");
                        } else {
                            print_val("First Actor", first_actor);
                            if (first_actor != 0) {
                                if (read_remote_memory(task, first_actor + OFFSET_MESH, &mesh, sizeof(mesh))) {
                                    printk(KERN_ERR "[BGMI] FAILED to read Mesh\n");
                                } else {
                                    print_val("Mesh", mesh);
                                    if (mesh != 0) {
                                        unsigned long lrt;
                                        if (read_remote_memory(task, mesh + OFFSET_LAST_RENDER_TIME, &lrt, sizeof(lrt))) {
                                            printk(KERN_ERR "[BGMI] FAILED: LastRenderTime\n");
                                        } else {
                                            print_val("LastRenderTime", lrt);
                                        }
                                    }
                                }
                                if (read_remote_memory(task, first_actor + OFFSET_ROOT_COMPONENT, &root_comp, sizeof(root_comp))) {
                                    printk(KERN_ERR "[BGMI] FAILED: RootComponent\n");
                                } else {
                                    print_val("RootComponent", root_comp);
                                    if (root_comp != 0) {
                                        if (read_remote_memory(task, root_comp + OFFSET_POSITION, &position, sizeof(position))) {
                                            printk(KERN_ERR "[BGMI] FAILED: Position\n");
                                        } else {
                                            unsigned int *pos_ints = (unsigned int *)position;
                                            printk(KERN_INFO "[BGMI] Position (raw): 0x%08x 0x%08x 0x%08x\n",
                                                   pos_ints[0], pos_ints[1], pos_ints[2]);
                                        }
                                    }
                                }
                                if (read_remote_memory(task, first_actor + OFFSET_HEALTH, &health, sizeof(health))) {
                                    printk(KERN_ERR "[BGMI] FAILED: Health\n");
                                } else {
                                    print_int("Health", health);
                                }
                                if (read_remote_memory(task, first_actor + OFFSET_TEAM_ID, &team_id, sizeof(team_id))) {
                                    printk(KERN_ERR "[BGMI] FAILED: TeamID\n");
                                } else {
                                    print_int("TeamID", (int)team_id);
                                }
                                {
                                    unsigned long name_ptr;
                                    if (read_remote_memory(task, first_actor + OFFSET_PLAYER_NAME, &name_ptr, sizeof(name_ptr))) {
                                        printk(KERN_ERR "[BGMI] FAILED: PlayerName pointer\n");
                                    } else if (name_ptr != 0) {
                                        if (read_remote_memory(task, name_ptr, name, 31)) {
                                            printk(KERN_ERR "[BGMI] FAILED: PlayerName data\n");
                                        } else {
                                            name[31] = 0;
                                            printk(KERN_INFO "[BGMI] PlayerName: %s\n", name);
                                        }
                                    }
                                }
                                if (read_remote_memory(task, first_actor + OFFSET_B_IS_AI, &is_ai, sizeof(is_ai))) {
                                    printk(KERN_ERR "[BGMI] FAILED: bIsAI\n");
                                } else {
                                    printk(KERN_INFO "[BGMI] bIsAI: %s\n", is_ai ? "true (BOT)" : "false (Player)");
                                }
                            }
                        }
                    }
                }
            }
        }

        // Local player chain
        {
            unsigned long game_instance, local_players_array, local_player, player_controller, local_pawn;
            printk(KERN_INFO "[BGMI] --- Testing Local Player chain ---\n");
            if (read_remote_memory(task, gworld + OFFSET_UWORLD_OWNING_GAMEINSTANCE, &game_instance, sizeof(game_instance))) {
                printk(KERN_ERR "[BGMI] FAILED: OwningGameInstance\n");
            } else {
                print_val("GameInstance", game_instance);
                if (game_instance != 0) {
                    if (read_remote_memory(task, game_instance + OFFSET_GAMEINSTANCE_LOCALPLAYERS, &local_players_array, sizeof(local_players_array))) {
                        printk(KERN_ERR "[BGMI] FAILED: LocalPlayers array\n");
                    } else {
                        print_val("LocalPlayers Array", local_players_array);
                        if (local_players_array != 0) {
                            if (read_remote_memory(task, local_players_array, &local_player, sizeof(local_player))) {
                                printk(KERN_ERR "[BGMI] FAILED: LocalPlayer[0]\n");
                            } else {
                                print_val("LocalPlayer[0]", local_player);
                                if (local_player != 0) {
                                    if (read_remote_memory(task, local_player + OFFSET_LOCALPLAYER_PLAYERCONTROLLER, &player_controller, sizeof(player_controller))) {
                                        printk(KERN_ERR "[BGMI] FAILED: PlayerController\n");
                                    } else {
                                        print_val("PlayerController", player_controller);
                                        if (player_controller != 0) {
                                            if (read_remote_memory(task, player_controller + OFFSET_ACKNOWLEDGED_PAWN, &local_pawn, sizeof(local_pawn))) {
                                                printk(KERN_ERR "[BGMI] FAILED: AcknowledgedPawn\n");
                                            } else {
                                                print_val("Local Pawn", local_pawn);
                                                if (local_pawn != 0) {
                                                    unsigned long ltid;
                                                    if (read_remote_memory(task, local_pawn + OFFSET_TEAM_ID, &ltid, sizeof(ltid))) {
                                                        printk(KERN_ERR "[BGMI] FAILED: Local TeamID\n");
                                                    } else {
                                                        local_pawn_team_id = ltid;
                                                        print_int("Local Pawn TeamID", (int)local_pawn_team_id);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    printk(KERN_INFO "[BGMI] --- Testing VMatrix & W2S function ---\n");
    {
        unsigned int vmatrix[16];
        if (read_remote_memory(task, abs_vmatrix, vmatrix, sizeof(vmatrix))) {
            printk(KERN_ERR "[BGMI] FAILED to read VMatrix\n");
        } else {
            printk(KERN_INFO "[BGMI] VMatrix first 4 words: 0x%08x 0x%08x 0x%08x 0x%08x\n",
                   vmatrix[0], vmatrix[1], vmatrix[2], vmatrix[3]);
        }
    }
    {
        unsigned char code[8];
        if (read_remote_memory(task, abs_w2s_func, code, sizeof(code))) {
            printk(KERN_ERR "[BGMI] FAILED to read W2S function code\n");
        } else {
            printk(KERN_INFO "[BGMI] W2S first bytes: %02x %02x %02x %02x ...\n",
                   code[0], code[1], code[2], code[3]);
        }
    }

    printk(KERN_INFO "[BGMI] Offset check complete. Review dmesg output.\n");
    return 0;
}

static void __exit bgmi_checker_exit(void)
{
    printk(KERN_INFO "[BGMI] Module unloaded\n");
}

module_init(bgmi_checker_init);
module_exit(bgmi_checker_exit);
