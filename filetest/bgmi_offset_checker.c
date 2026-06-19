/*
 * bgmi_offset_checker_kernel.c – Kernel module to test BGMI memory offsets
 *
 * Build (if you have kernel source tree):
 *   make -C /path/to/kernel/out M=$(pwd) modules ARCH=arm64
 *
 * Then push bgmi_offset_checker.ko to device and:
 *   su -c insmod bgmi_offset_checker.ko
 *   su -c dmesg | tail -50
 *   su -c rmmod bgmi_offset_checker
 *
 * All output goes to the kernel log (dmesg).
 */

#define pr_fmt(fmt) "BGMI_offset: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/version.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>

// ---------- OFFSETS (from your JSON) ----------
// Base
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

// ComponentToWorld
#define OFF_USceneComponent_ComponentToWorld  0x1C0
#define OFF_FTransform_Rotation               0x0
#define OFF_FTransform_Translation            0x10
#define OFF_FTransform_Scale                  0x20
#define FTransform_Size                       40

// Visibility
#define OFF_UPrimitiveComponent_LastSubmitTime  0x2A0
#define OFF_UPrimitiveComponent_LastRenderTime  0x2A4

// Members
#define OFF_PlayerKey       0x238
#define OFF_RootComponent   0x180
#define OFF_bDead           0x72C
#define OFF_bEnsure         0x259

// Traversal chains
#define OFF_GWorld_to_PersistentLevel   0x20
#define OFF_ULevel_to_GameInstance      0x70
#define OFF_GameInstance_to_LocalPlayers 0x38
#define OFF_LocalPlayer_to_PlayerController 0x30
#define OFF_PlayerController_to_AcknowledgedPawn 0x2A0

#define OFF_PlayerController_to_PlayerCameraManager 0x348
#define OFF_PlayerCameraManager_to_CameraCacheEntry 0x350
#define OFF_CameraCacheEntry_Location  0x0
#define OFF_CameraCacheEntry_Rotation  0xC
#define OFF_CameraCacheEntry_FOV       0x18

#define OFF_PersistentLevel_to_Actors  0x98

#define OFF_ASTExtraPlayerCharacter_to_Mesh  0x320
#define OFF_Mesh_to_ComponentSpaceTransforms 0x710

#define OFF_ASTExtraPlayerCharacter_to_PlayerState 0x398
#define OFF_PlayerState_TeamID      0x70
#define OFF_PlayerState_Health      0x1A8
#define OFF_PlayerState_HealthMax   0x1B0
#define OFF_PlayerState_PlayerName  0x2B0

#define OFF_USceneComponent_RelativeLocation 0x11C

// ---------- Helper: read remote process memory ----------
static int read_remote_mem(pid_t pid, unsigned long addr, void *buf, size_t len)
{
    struct task_struct *task;
    struct mm_struct *mm;
    int ret;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (!task) {
        rcu_read_unlock();
        pr_err("task %d not found\n", pid);
        return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        pr_err("cannot get mm for pid %d\n", pid);
        return -EINVAL;
    }

    // access_remote_vm: returns #bytes NOT copied, so 0 = success
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
    ret = access_remote_vm(mm, addr, buf, len, 0);
#else
    // older kernels need FOLL_FORCE? we can use get_user_pages_remote, but access_remote_vm is simpler
    mmap_read_lock(mm);
    ret = access_remote_vm(mm, addr, buf, len, FOLL_FORCE);
    mmap_read_unlock(mm);
    mmput(mm);
    return (ret == 0) ? 0 : -EFAULT;
#endif
    mmput(mm);
    return (ret == 0) ? 0 : -EFAULT;
}

static int read_ptr_remote(pid_t pid, unsigned long addr, unsigned long *out)
{
    return read_remote_mem(pid, addr, out, sizeof(*out));
}

// ---------- Find library base in remote process ----------
static unsigned long get_library_base(pid_t pid, const char *lib_name)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned long base = 0;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (!task) {
        rcu_read_unlock();
        return 0;
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return 0;

    mmap_read_lock(mm);
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        struct file *file = vma->vm_file;
        if (!file)
            continue;
        // Get dentry name
        const char *name = file->f_path.dentry->d_name.name;
        if (name && strstr(name, lib_name)) {
            base = vma->vm_start;
            break;
        }
    }
    mmap_read_unlock(mm);
    mmput(mm);
    return base;
}

// ---------- Main test function ----------
static int __init test_offsets(void)
{
    pid_t pid;
    unsigned long libbase;
    int ret;

    // 1. Find PID
    pid = find_pid_of("com.pubg.imobile");
    if (pid <= 0) {
        pr_err("BGMI process not found\n");
        return -ENOENT;
    }
    pr_info("BGMI PID = %d\n", pid);

    // 2. Find libUE4.so base
    libbase = get_library_base(pid, "libUE4.so");
    if (!libbase) {
        pr_err("libUE4.so base not found\n");
        return -EFAULT;
    }
    pr_info("libUE4.so base = 0x%lx\n", libbase);

    // ---------- Test Base Offsets ----------
    pr_info("Testing Base Offsets...\n");
    struct {
        char *name;
        unsigned long off;
    } base_tests[] = {
        {"GNames", OFF_GNames},
        {"GUObject", OFF_GUObject},
        {"GWorld", OFF_GWorld},
        {"GetActorArray", OFF_GetActorArray},
        {"GNativeAndroidApp", OFF_GNativeAndroidApp},
    };
    for (int i = 0; i < ARRAY_SIZE(base_tests); i++) {
        unsigned long addr = libbase + base_tests[i].off;
        unsigned long val = 0;
        if (read_ptr_remote(pid, addr, &val) == 0)
            pr_info("  [OK] %-20s = 0x%lx\n", base_tests[i].name, val);
        else
            pr_err("  [FAIL] %-20s at 0x%lx\n", base_tests[i].name, addr);
    }

    // ---------- Test Traversal: Local Player ----------
    pr_info("Traversing LocalPlayer chain...\n");
    unsigned long gworld_ptr_addr = libbase + OFF_GWorld;
    unsigned long gworld = 0;
    if (read_ptr_remote(pid, gworld_ptr_addr, &gworld) != 0) {
        pr_err("Cannot read GWorld pointer\n");
        goto out;
    }
    if (gworld < 0x1000) {
        pr_err("GWorld pointer invalid: 0x%lx\n", gworld);
        goto out;
    }
    pr_info("GWorld = 0x%lx\n", gworld);

    // Step: PersistentLevel
    unsigned long level = 0;
    if (read_ptr_remote(pid, gworld + OFF_GWorld_to_PersistentLevel, &level) != 0)
        goto chain_fail;
    pr_info("ULevel = 0x%lx\n", level);

    // Step: GameInstance
    unsigned long gameinst = 0;
    if (read_ptr_remote(pid, level + OFF_ULevel_to_GameInstance, &gameinst) != 0)
        goto chain_fail;
    pr_info("GameInstance = 0x%lx\n", gameinst);

    // Step: LocalPlayers array (TArray: Data, Count, Max)
    unsigned long localplayers_data = 0;
    int localplayers_count = 0;
    ret = read_remote_mem(pid, gameinst + OFF_GameInstance_to_LocalPlayers,
                &localplayers_data, sizeof(localplayers_data));
    if (ret) goto chain_fail;
    ret = read_remote_mem(pid, gameinst + OFF_GameInstance_to_LocalPlayers + 4,
                &localplayers_count, sizeof(localplayers_count));
    if (ret) goto chain_fail;
    pr_info("LocalPlayers.Data = 0x%lx, Count = %d\n", localplayers_data, localplayers_count);
    if (localplayers_count <= 0 || !localplayers_data) {
        pr_err("LocalPlayers empty\n");
        goto chain_fail;
    }

    // Step: LocalPlayer[0]
    unsigned long localplayer = 0;
    if (read_ptr_remote(pid, localplayers_data, &localplayer) != 0)
        goto chain_fail;
    pr_info("LocalPlayer[0] = 0x%lx\n", localplayer);

    // Step: PlayerController
    unsigned long playerctrl = 0;
    if (read_ptr_remote(pid, localplayer + OFF_LocalPlayer_to_PlayerController, &playerctrl) != 0)
        goto chain_fail;
    pr_info("PlayerController = 0x%lx\n", playerctrl);

    // Step: Pawn (AcknowledgedPawn)
    unsigned long pawn = 0;
    if (read_ptr_remote(pid, playerctrl + OFF_PlayerController_to_AcknowledgedPawn, &pawn) != 0)
        goto chain_fail;
    pr_info("AcknowledgedPawn = 0x%lx\n", pawn);

    // Test member offsets on pawn
    pr_info("Testing member offsets on pawn (0x%lx):\n", pawn);
    {
        unsigned long val;
        if (read_ptr_remote(pid, pawn + OFF_bDead, &val) == 0)
            pr_info("  bDead = 0x%lx\n", val);
        if (read_ptr_remote(pid, pawn + OFF_bEnsure, &val) == 0)
            pr_info("  bEnsure (BotFlag) = 0x%lx\n", val);
        if (read_ptr_remote(pid, pawn + OFF_PlayerKey, &val) == 0)
            pr_info("  PlayerKey = 0x%lx\n", val);
    }

    // RootComponent and RelativeLocation
    unsigned long rootcomp = 0;
    if (read_ptr_remote(pid, pawn + OFF_RootComponent, &rootcomp) == 0 && rootcomp > 0x1000) {
        float loc[3];
        if (read_remote_mem(pid, rootcomp + OFF_USceneComponent_RelativeLocation, loc, sizeof(loc)) == 0)
            pr_info("  RelativeLocation = (%f, %f, %f)\n", loc[0], loc[1], loc[2]);
    }

    // Mesh
    unsigned long mesh = 0;
    if (read_ptr_remote(pid, pawn + OFF_ASTExtraPlayerCharacter_to_Mesh, &mesh) == 0 && mesh > 0x1000) {
        pr_info("Mesh = 0x%lx\n", mesh);

        // Bone array
        unsigned long bonearray_data = 0;
        if (read_ptr_remote(pid, mesh + OFF_Mesh_to_ComponentSpaceTransforms, &bonearray_data) == 0) {
            pr_info("  BoneArray.Data = 0x%lx\n", bonearray_data);
            if (bonearray_data > 0x1000) {
                float translation[3];
                if (read_remote_mem(pid, bonearray_data + OFF_FTransform_Translation, translation, sizeof(translation)) == 0)
                    pr_info("    Bone[0] Translation = (%f, %f, %f)\n", translation[0], translation[1], translation[2]);
            }
        }

        // Visibility times
        float submit_t, render_t;
        if (read_remote_mem(pid, mesh + OFF_UPrimitiveComponent_LastSubmitTime, &submit_t, sizeof(float)) == 0 &&
            read_remote_mem(pid, mesh + OFF_UPrimitiveComponent_LastRenderTime, &render_t, sizeof(float)) == 0)
            pr_info("  LastSubmitTime = %f, LastRenderTime = %f\n", submit_t, render_t);

        // ComponentToWorld
        float ctw_loc[3];
        if (read_remote_mem(pid, mesh + OFF_USceneComponent_ComponentToWorld + OFF_FTransform_Translation, ctw_loc, sizeof(ctw_loc)) == 0)
            pr_info("  ComponentToWorld.Translation = (%f, %f, %f)\n", ctw_loc[0], ctw_loc[1], ctw_loc[2]);
    }

    // PlayerState
    unsigned long playerstate = 0;
    if (read_ptr_remote(pid, pawn + OFF_ASTExtraPlayerCharacter_to_PlayerState, &playerstate) == 0 && playerstate > 0x1000) {
        int team;
        float hp, maxhp;
        read_remote_mem(pid, playerstate + OFF_PlayerState_TeamID, &team, sizeof(team));
        read_remote_mem(pid, playerstate + OFF_PlayerState_Health, &hp, sizeof(hp));
        read_remote_mem(pid, playerstate + OFF_PlayerState_HealthMax, &maxhp, sizeof(maxhp));
        pr_info("PlayerState: TeamID=%d  Health=%.1f/%.1f\n", team, hp, maxhp);

        unsigned long name_data; int name_count, name_max;
        if (read_ptr_remote(pid, playerstate + OFF_PlayerState_PlayerName, &name_data) == 0) {
            read_remote_mem(pid, playerstate + OFF_PlayerState_PlayerName + 8, &name_count, sizeof(name_count));
            read_remote_mem(pid, playerstate + OFF_PlayerState_PlayerName + 12, &name_max, sizeof(name_max));
            pr_info("  PlayerName: Data=0x%lx Count=%d Max=%d\n", name_data, name_count, name_max);
        }
    }

    pr_info("All tests finished. Check dmesg for results.\n");
    return -EINVAL; // don't stay loaded, just for testing

chain_fail:
    pr_err("Chain broken at some step\n");
    return -EFAULT;

out:
    pr_err("Exiting with error\n");
    return -EFAULT;
}

static void __exit test_exit(void)
{
    pr_info("Module removed\n");
}

module_init(test_offsets);
module_exit(test_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("BGMI Offset Checker Kernel Module");
