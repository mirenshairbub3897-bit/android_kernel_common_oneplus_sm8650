/*
 * BGMI Offset Validator for Rooted Android
 * Compile: clang -static -o check_offsets check_offsets.c
 * Run:     su -c ./check_offsets
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <errno.h>

// =================== OFFSETS FROM JSON ===================
// Base Offsets
#define OFF_GNames              0x8394964
#define OFF_GUObject            0xe22f8d0
#define OFF_GWorld              0x8d35a40
#define OFF_GetActorArray       0xa1018ac
#define OFF_GNativeAndroidApp   0xdf74398

// Actor Identification
#define OFF_UObject_ClassPrivate    0x10
#define OFF_UObject_NamePrivate     0x18
#define OFF_FName_ComparisonIndex   0x0
#define OFF_UClass_SuperStruct      0x30

// Component to World
#define OFF_USceneComponent_ComponentToWorld  0x1C0
#define OFF_FTransform_Rotation               0x0
#define OFF_FTransform_Translation            0x10
#define OFF_FTransform_Scale                  0x20
#define FTransform_Size                       40

// Visibility Check
#define OFF_UPrimitiveComponent_LastSubmitTime  0x2A0
#define OFF_UPrimitiveComponent_LastRenderTime  0x2A4

// Member Offsets (relative to player character)
#define OFF_PlayerKey       0x238
#define OFF_RootComponent   0x180
#define OFF_bDead           0x72C
#define OFF_bEnsure         0x259

// Traversal Chain Offsets (from the strings)
// ToLocalPlayer
#define OFF_GWorld_to_PersistentLevel   0x20
#define OFF_ULevel_to_GameInstance      0x70
#define OFF_GameInstance_to_LocalPlayers 0x38   // TArray
#define OFF_LocalPlayer_to_PlayerController 0x30
#define OFF_PlayerController_to_AcknowledgedPawn 0x2A0

// ToCamera
#define OFF_PlayerController_to_PlayerCameraManager 0x348
#define OFF_PlayerCameraManager_to_CameraCacheEntry 0x350
#define OFF_CameraCacheEntry_Location  0x0
#define OFF_CameraCacheEntry_Rotation  0xC
#define OFF_CameraCacheEntry_FOV       0x18

// ToActorArray
#define OFF_PersistentLevel_to_Actors  0x98    // TArray

// ToBoneArray
#define OFF_ASTExtraPlayerCharacter_to_Mesh  0x320
#define OFF_Mesh_to_ComponentSpaceTransforms 0x710  // TArray<FTransform>

// ToPlayerState
#define OFF_ASTExtraPlayerCharacter_to_PlayerState 0x398
#define OFF_PlayerState_TeamID      0x70
#define OFF_PlayerState_Health      0x1A8
#define OFF_PlayerState_HealthMax   0x1B0
#define OFF_PlayerState_PlayerName  0x2B0   // FString

// RelativeLocation (within RootComponent)
#define OFF_USceneComponent_RelativeLocation 0x11C

// =========================================================

// ---------- Utility functions ----------
pid_t find_pid(const char *package_name) {
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *ent;
    pid_t pid = -1;
    while ((ent = readdir(d))) {
        if (ent->d_type != DT_DIR) continue;
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
        char cmdline_path[256];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", ent->d_name);
        int fd = open(cmdline_path, O_RDONLY);
        if (fd < 0) continue;
        char buf[256];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = 0;
            if (strcmp(buf, package_name) == 0) {
                pid = atoi(ent->d_name);
                break;
            }
        }
    }
    closedir(d);
    return pid;
}

unsigned long get_module_base(pid_t pid, const char *module) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) return 0;
    char line[512];
    unsigned long base = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, module)) {
            base = strtoul(line, NULL, 16);
            break;
        }
    }
    fclose(fp);
    return base;
}

// Read memory from process using /proc/pid/mem
int mem_read(pid_t pid, unsigned long addr, void *buf, size_t size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    if (lseek(fd, (off_t)addr, SEEK_SET) == -1) {
        close(fd);
        return -1;
    }
    ssize_t ret = read(fd, buf, size);
    close(fd);
    return (ret == (ssize_t)size) ? 0 : -1;
}

// Try to read an 8‑byte value, return 0 on success
int read_ptr(pid_t pid, unsigned long addr, unsigned long *out) {
    return mem_read(pid, addr, out, sizeof(*out));
}

// Check if a pointer is “plausible” (non‑zero, and within typical address range)
int is_valid_ptr(unsigned long ptr) {
    return ptr > 0x1000 && ptr < 0x7fffffffffffUL;
}

// ===================== TEST FUNCTIONS =====================

void test_base_offsets(pid_t pid, unsigned long libbase) {
    printf("[BASE OFFSETS]\n");
    struct { char *name; unsigned long off; } tests[] = {
        {"GNames",             OFF_GNames},
        {"GUObject",           OFF_GUObject},
        {"GWorld (static ptr)",OFF_GWorld},
        {"GetActorArray",      OFF_GetActorArray},
        {"GNativeAndroidApp",  OFF_GNativeAndroidApp},
    };
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        unsigned long addr = libbase + tests[i].off;
        unsigned long val = 0;
        if (read_ptr(pid, addr, &val) == 0) {
            printf("  [OK] %-20s = 0x%lx (addr 0x%lx)\n", tests[i].name, val, addr);
        } else {
            printf("  [FAIL] %-20s at 0x%lx : %s\n", tests[i].name, addr, strerror(errno));
        }
    }
}

void test_actor_id_offsets(pid_t pid, unsigned long libbase) {
    printf("\n[ACTOR IDENTIFICATION OFFSETS] (static, no object needed)\n");
    unsigned long guobject_addr = libbase + OFF_GUObject;
    unsigned long guobject_ptr = 0;
    if (read_ptr(pid, guobject_addr, &guobject_ptr) != 0 || !is_valid_ptr(guobject_ptr)) {
        printf("  GUObject not valid, skip further tests.\n");
        return;
    }
    // Now GUObject pointer is the FUObjectArray*.
    // We can try to read its internal structure, but we lack the exact layout.
    // Just check that the offsets themselves are in a readable region.
    unsigned long test_addrs[] = {
        guobject_ptr + 0,          // first bytes
        guobject_ptr + OFF_UObject_ClassPrivate,   // nonsense unless we have an object
    };
    for (size_t i = 0; i < sizeof(test_addrs)/sizeof(test_addrs[0]); i++) {
        unsigned long val = 0;
        if (read_ptr(pid, test_addrs[i], &val) == 0) {
            printf("  [OK] Read 0x%lx : 0x%lx\n", test_addrs[i], val);
        } else {
            printf("  [FAIL] Read 0x%lx : %s\n", test_addrs[i], strerror(errno));
        }
    }
}

// Follow a pointer chain, printing each step
int follow_chain(pid_t pid, unsigned long start, const unsigned long *offsets, int count, const char *desc) {
    printf("\n[CHAIN] %s\n", desc);
    unsigned long addr = start;
    for (int i = 0; i < count; i++) {
        unsigned long next = 0;
        if (read_ptr(pid, addr, &next) != 0) {
            printf("  [FAIL] step %d: read at 0x%lx failed : %s\n", i+1, addr, strerror(errno));
            return -1;
        }
        printf("  step %d: 0x%lx -> 0x%lx\n", i+1, addr, next);
        if (!is_valid_ptr(next)) {
            printf("  [WARN] step %d: pointer 0x%lx does not look valid\n", i+1, next);
            // But we still add offset and continue
        }
        addr = next + offsets[i];
    }
    printf("  final address: 0x%lx\n", addr);
    // Try to read the final target (e.g., a float or int)
    unsigned long final_val = 0;
    if (read_ptr(pid, addr, &final_val) == 0) {
        printf("  [OK] final read success: 0x%lx\n", final_val);
    } else {
        printf("  [FAIL] final read at 0x%lx : %s\n", addr, strerror(errno));
    }
    return 0;
}

void test_traversals(pid_t pid, unsigned long libbase) {
    // Get GWorld pointer
    unsigned long gworld_ptr_addr = libbase + OFF_GWorld;
    unsigned long gworld = 0;
    if (read_ptr(pid, gworld_ptr_addr, &gworld) != 0 || !is_valid_ptr(gworld)) {
        printf("  GWorld not found, skipping all traversals.\n");
        return;
    }
    printf("\n[GWorld] = 0x%lx\n", gworld);

    // ---- Local Player Chain ----
    {
        unsigned long offsets[] = {
            OFF_GWorld_to_PersistentLevel,
            OFF_ULevel_to_GameInstance,
            OFF_GameInstance_to_LocalPlayers + 0x0, // TArray data pointer (assuming inline layout)
            // LocalPlayers[0] is at data+0, no offset needed
            0, // The pointer read from the array is LocalPlayer*
            OFF_LocalPlayer_to_PlayerController,
            OFF_PlayerController_to_AcknowledgedPawn,
        };
        // Actually the chain description is: GWorld +0x20 -> ULevel*
        // Then ULevel +0x70 -> GameInstance*
        // Then GameInstance +0x38 -> LocalPlayers (TArray)
        // LocalPlayers.Data + 0*8 = first LocalPlayer*
        // LocalPlayer +0x30 = PlayerController*
        // PlayerController +0x2A0 = Pawn*
        // We'll follow step by step manually.
        printf("\n[Traversal] LocalPlayer chain:\n");
        unsigned long addr = gworld;
        // 1) GWorld + 0x20 -> ULevel
        if (read_ptr(pid, addr + OFF_GWorld_to_PersistentLevel, &addr) != 0) {
            printf("  FAIL at GWorld + 0x20\n"); return;
        }
        printf("  ULevel: 0x%lx\n", addr);
        if (!is_valid_ptr(addr)) goto loc_fail;
        // 2) ULevel + 0x70 -> GameInstance
        if (read_ptr(pid, addr + OFF_ULevel_to_GameInstance, &addr) != 0) goto loc_fail;
        printf("  GameInstance: 0x%lx\n", addr);
        if (!is_valid_ptr(addr)) goto loc_fail;
        // 3) GameInstance + 0x38 -> LocalPlayers (TArray)
        // TArray header: Data pointer at +0, Count at +4, Max at +8.
        unsigned long loc_array_data = 0;
        if (read_ptr(pid, addr + OFF_GameInstance_to_LocalPlayers, &loc_array_data) != 0) goto loc_fail;
        printf("  LocalPlayers.Data: 0x%lx\n", loc_array_data);
        if (!is_valid_ptr(loc_array_data)) goto loc_fail;
        // 4) LocalPlayers[0]
        unsigned long local_player = 0;
        if (read_ptr(pid, loc_array_data, &local_player) != 0) goto loc_fail;
        printf("  LocalPlayer[0]: 0x%lx\n", local_player);
        if (!is_valid_ptr(local_player)) goto loc_fail;
        // 5) LocalPlayer + 0x30 -> PlayerController
        if (read_ptr(pid, local_player + OFF_LocalPlayer_to_PlayerController, &addr) != 0) goto loc_fail;
        printf("  PlayerController: 0x%lx\n", addr);
        if (!is_valid_ptr(addr)) goto loc_fail;
        // 6) PlayerController + 0x2A0 -> Pawn
        unsigned long pawn = 0;
        if (read_ptr(pid, addr + OFF_PlayerController_to_AcknowledgedPawn, &pawn) != 0) goto loc_fail;
        printf("  AcknowledgedPawn: 0x%lx\n", pawn);
        if (!is_valid_ptr(pawn)) goto loc_fail;

        // Now test member offsets on this pawn (player character)
        printf("\n[Member Offsets on player 0x%lx]\n", pawn);
        struct { unsigned long off; char *name; } mem_tests[] = {
            {OFF_bDead, "bDead"},
            {OFF_bEnsure, "bEnsure (BotFlag)"},
            {OFF_PlayerKey, "PlayerKey"},
            {OFF_RootComponent, "RootComponent"},
        };
        for (size_t i=0; i<sizeof(mem_tests)/sizeof(mem_tests[0]); i++) {
            unsigned long val = 0;
            if (read_ptr(pid, pawn + mem_tests[i].off, &val) == 0)
                printf("    [OK] %-20s : 0x%lx\n", mem_tests[i].name, val);
            else
                printf("    [FAIL] %-20s : %s\n", mem_tests[i].name, strerror(errno));
        }

        // RootComponent -> RelativeLocation
        unsigned long root_comp = 0;
        if (read_ptr(pid, pawn + OFF_RootComponent, &root_comp) == 0 && is_valid_ptr(root_comp)) {
            float loc[3] = {0};
            if (mem_read(pid, root_comp + OFF_USceneComponent_RelativeLocation, loc, sizeof(loc)) == 0) {
                printf("    RelativeLocation: (%f, %f, %f)\n", loc[0], loc[1], loc[2]);
            } else {
                printf("    [FAIL] RelativeLocation read\n");
            }
        }

        // Mesh -> Bone Array and Visibility
        unsigned long mesh = 0;
        if (read_ptr(pid, pawn + OFF_ASTExtraPlayerCharacter_to_Mesh, &mesh) == 0 && is_valid_ptr(mesh)) {
            printf("\n[Bone & Visibility on Mesh 0x%lx]\n", mesh);
            // ComponentSpaceTransforms array
            unsigned long bone_array_data = 0;
            if (read_ptr(pid, mesh + OFF_Mesh_to_ComponentSpaceTransforms, &bone_array_data) == 0) {
                printf("  BoneArray.Data: 0x%lx\n", bone_array_data);
                // Try reading first bone transform (index 0)
                if (is_valid_ptr(bone_array_data)) {
                    float bone_translation[3];
                    if (mem_read(pid, bone_array_data + OFF_FTransform_Translation, bone_translation, sizeof(bone_translation)) == 0)
                        printf("    Bone[0] Translation: (%f, %f, %f)\n", bone_translation[0], bone_translation[1], bone_translation[2]);
                    else
                        printf("    [FAIL] Bone[0] read\n");
                }
            } else {
                printf("  [FAIL] BoneArray pointer\n");
            }

            // Visibility times
            float submit_time = 0, render_time = 0;
            if (mem_read(pid, mesh + OFF_UPrimitiveComponent_LastSubmitTime, &submit_time, sizeof(float)) == 0 &&
                mem_read(pid, mesh + OFF_UPrimitiveComponent_LastRenderTime, &render_time, sizeof(float)) == 0) {
                printf("  LastSubmitTime: %f, LastRenderTime: %f\n", submit_time, render_time);
            } else {
                printf("  [FAIL] Visibility times\n");
            }

            // ComponentToWorld (FTransform) at mesh + OFF_USceneComponent_ComponentToWorld
            float ctw_translation[3];
            if (mem_read(pid, mesh + OFF_USceneComponent_ComponentToWorld + OFF_FTransform_Translation, ctw_translation, sizeof(ctw_translation)) == 0)
                printf("  ComponentToWorld.Translation: (%f, %f, %f)\n", ctw_translation[0], ctw_translation[1], ctw_translation[2]);
            else
                printf("  [FAIL] ComponentToWorld\n");
        } else {
            printf("  [FAIL] Mesh pointer\n");
        }

        // PlayerState
        unsigned long player_state = 0;
        if (read_ptr(pid, pawn + OFF_ASTExtraPlayerCharacter_to_PlayerState, &player_state) == 0 && is_valid_ptr(player_state)) {
            printf("\n[PlayerState 0x%lx]\n", player_state);
            int team = 0; float hp=0, maxhp=0;
            unsigned long name_data=0; int name_count=0, name_max=0;
            mem_read(pid, player_state + OFF_PlayerState_TeamID, &team, sizeof(team));
            mem_read(pid, player_state + OFF_PlayerState_Health, &hp, sizeof(hp));
            mem_read(pid, player_state + OFF_PlayerState_HealthMax, &maxhp, sizeof(maxhp));
            // FString PlayerName at 0x2B0 (Data, Count, Max)
            if (read_ptr(pid, player_state + OFF_PlayerState_PlayerName, &name_data) == 0) {
                mem_read(pid, player_state + OFF_PlayerState_PlayerName + 8, &name_count, sizeof(name_count));
                mem_read(pid, player_state + OFF_PlayerState_PlayerName + 12, &name_max, sizeof(name_max));
            }
            printf("  TeamID: %d  Health: %.1f/%.1f\n", team, hp, maxhp);
            printf("  PlayerName: Data=0x%lx Count=%d Max=%d\n", name_data, name_count, name_max);
        } else {
            printf("  [FAIL] PlayerState\n");
        }
        return;
loc_fail:
        printf("  [FAIL] Chain broken.\n");
    }
}

int main() {
    puts("=== BGMI Offset Validator ===");
    pid_t pid = find_pid("com.pubg.imobile");
    if (pid <= 0) {
        fprintf(stderr, "Error: BGMI process not found. Is the game running?\n");
        return 1;
    }
    printf("Found PID: %d\n", pid);

    unsigned long libbase = get_module_base(pid, "libUE4.so");
    if (!libbase) {
        fprintf(stderr, "Error: libUE4.so base not found in /proc/%d/maps\n", pid);
        return 1;
    }
    printf("libUE4.so base: 0x%lx\n\n", libbase);

    test_base_offsets(pid, libbase);
    test_actor_id_offsets(pid, libbase);
    test_traversals(pid, libbase);

    puts("\nDone.");
    return 0;
}
