/*
 * bgmi_offset_checker_kernel.c – Kernel module to verify BGMI memory offsets
 *
 * Build:
 *   make -C /path/to/kernel/out M=$(pwd) ARCH=arm64 LLVM=1 modules
 *
 * Usage:
 *   insmod bgmi_offset_checker.ko pid=$(pidof com.pubg.imobile)
 *   dmesg | tail -n 100
 *   rmmod bgmi_offset_checker
 */

#define pr_fmt(fmt) "BGMI_off: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/mmap_lock.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/string.h>

/* ---------- OFFSETS (from JSON) ---------- */
#define OFF_GNames              0x8394964
#define OFF_GUObject            0xe22f8d0
#define OFF_GWorld              0x8d35a40
#define OFF_GetActorArray       0xa1018ac
#define OFF_GNativeAndroidApp   0xdf74398

#define OFF_UObject_ClassPrivate    0x10
#define OFF_UObject_NamePrivate     0x18
#define OFF_FName_ComparisonIndex   0x0
#define OFF_UClass_SuperStruct      0x30

#define OFF_USceneComponent_ComponentToWorld  0x1C0
#define OFF_FTransform_Rotation               0x0
#define OFF_FTransform_Translation            0x10
#define OFF_FTransform_Scale                  0x20
#define FTransform_Size                       40

#define OFF_UPrimitiveComponent_LastSubmitTime  0x2A0
#define OFF_UPrimitiveComponent_LastRenderTime  0x2A4

#define OFF_PlayerKey       0x238
#define OFF_RootComponent   0x180
#define OFF_bDead           0x72C
#define OFF_bEnsure         0x259

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

static int target_pid = 0;
module_param_named(pid, target_pid, int, 0);
MODULE_PARM_DESC(pid, "PID of BGMI process");

/* ---------- read remote process memory ---------- */
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

    ret = access_remote_vm(mm, addr, buf, len, 0);
    mmput(mm);
    return (ret == 0) ? 0 : -EFAULT;
}

static int read_ptr_remote(pid_t pid, unsigned long addr, unsigned long *out)
{
    return read_remote_mem(pid, addr, out, sizeof(*out));
}

/* ---------- find library base in remote process ---------- */
static unsigned long get_library_base(pid_t pid, const char *lib_name)
{
    struct task_struct *task;
    struct mm_struct *mm = NULL;   /* explicit initialization */
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
    {
        VMA_ITERATOR(vmi, mm, 0);
        struct vm_area_struct *vma;
        for_each_vma(vmi, vma) {
            struct file *file = vma->vm_file;
            if (!file)
                continue;
            const char *name = file->f_path.dentry->d_name.name;
            if (name && strstr(name, lib_name)) {
                base = vma->vm_start;
                break;
            }
        }
    }
    mmap_read_unlock(mm);
    mmput(mm);
    return base;
}

/* ---------- test function ---------- */
static int __init test_offsets(void)
{
    unsigned long libbase;
    unsigned long gworld_ptr_addr, gworld, level, gameinst;
    unsigned long lp_data, localplayer, playerctrl, pawn;
    int lp_count;
    unsigned long rootcomp, mesh, bone_data, playerstate;
    float loc[3], submit_t, render_t, ctw_loc[3];
    int team;
    float hp, maxhp;
    unsigned long name_data; int name_count, name_max;

    if (target_pid <= 0) {
        pr_err("Invalid or missing PID. Use insmod bgmi_offset_checker.ko pid=...\n");
        return -EINVAL;
    }
    pr_info("BGMI PID = %d\n", target_pid);

    libbase = get_library_base(target_pid, "libUE4.so");
    if (!libbase) {
        pr_err("libUE4.so base not found\n");
        return -EFAULT;
    }
    pr_info("libUE4.so base = 0x%lx\n", libbase);

    /* Test Base Offsets */
    {
        struct { char *name; unsigned long off; } tests[] = {
            {"GNames", OFF_GNames},
            {"GUObject", OFF_GUObject},
            {"GWorld", OFF_GWorld},
            {"GetActorArray", OFF_GetActorArray},
            {"GNativeAndroidApp", OFF_GNativeAndroidApp},
        };
        for (int i = 0; i < ARRAY_SIZE(tests); i++) {
            unsigned long addr = libbase + tests[i].off;
            unsigned long val = 0;
            if (read_ptr_remote(target_pid, addr, &val) == 0)
                pr_info("  [OK] %-20s = 0x%lx\n", tests[i].name, val);
            else
                pr_err("  [FAIL] %-20s at 0x%lx\n", tests[i].name, addr);
        }
    }

    /* Traversal: LocalPlayer */
    pr_info("Traversing LocalPlayer chain...\n");
    gworld_ptr_addr = libbase + OFF_GWorld;
    if (read_ptr_remote(target_pid, gworld_ptr_addr, &gworld) != 0) {
        pr_err("Cannot read GWorld pointer\n");
        goto out;
    }
    if (gworld < 0x1000) {
        pr_err("GWorld invalid: 0x%lx\n", gworld);
        goto out;
    }
    pr_info("GWorld = 0x%lx\n", gworld);

    if (read_ptr_remote(target_pid, gworld + OFF_GWorld_to_PersistentLevel, &level) != 0)
        goto chain_fail;
    pr_info("ULevel = 0x%lx\n", level);

    if (read_ptr_remote(target_pid, level + OFF_ULevel_to_GameInstance, &gameinst) != 0)
        goto chain_fail;
    pr_info("GameInstance = 0x%lx\n", gameinst);

    if (read_remote_mem(target_pid, gameinst + OFF_GameInstance_to_LocalPlayers,
                        &lp_data, sizeof(lp_data)))
        goto chain_fail;
    if (read_remote_mem(target_pid, gameinst + OFF_GameInstance_to_LocalPlayers + 4,
                        &lp_count, sizeof(lp_count)))
        goto chain_fail;
    pr_info("LocalPlayers.Data = 0x%lx, Count = %d\n", lp_data, lp_count);
    if (lp_count <= 0 || lp_data == 0) {
        pr_err("LocalPlayers empty\n");
        goto chain_fail;
    }

    if (read_ptr_remote(target_pid, lp_data, &localplayer) != 0)
        goto chain_fail;
    pr_info("LocalPlayer[0] = 0x%lx\n", localplayer);

    if (read_ptr_remote(target_pid, localplayer + OFF_LocalPlayer_to_PlayerController, &playerctrl) != 0)
        goto chain_fail;
    pr_info("PlayerController = 0x%lx\n", playerctrl);

    if (read_ptr_remote(target_pid, playerctrl + OFF_PlayerController_to_AcknowledgedPawn, &pawn) != 0)
        goto chain_fail;
    pr_info("AcknowledgedPawn = 0x%lx\n", pawn);

    /* Member offsets on pawn */
    {
        unsigned long val;
        if (read_ptr_remote(target_pid, pawn + OFF_bDead, &val) == 0)
            pr_info("  bDead = 0x%lx\n", val);
        if (read_ptr_remote(target_pid, pawn + OFF_bEnsure, &val) == 0)
            pr_info("  bEnsure (BotFlag) = 0x%lx\n", val);
        if (read_ptr_remote(target_pid, pawn + OFF_PlayerKey, &val) == 0)
            pr_info("  PlayerKey = 0x%lx\n", val);
    }

    /* RootComponent */
    if (read_ptr_remote(target_pid, pawn + OFF_RootComponent, &rootcomp) == 0 && rootcomp > 0x1000) {
        if (read_remote_mem(target_pid, rootcomp + OFF_USceneComponent_RelativeLocation,
                            loc, sizeof(loc)) == 0)
            pr_info("  RelativeLocation = (%f, %f, %f)\n", loc[0], loc[1], loc[2]);
    }

    /* Mesh */
    if (read_ptr_remote(target_pid, pawn + OFF_ASTExtraPlayerCharacter_to_Mesh, &mesh) == 0 && mesh > 0x1000) {
        pr_info("Mesh = 0x%lx\n", mesh);
        if (read_ptr_remote(target_pid, mesh + OFF_Mesh_to_ComponentSpaceTransforms, &bone_data) == 0) {
            pr_info("  BoneArray.Data = 0x%lx\n", bone_data);
            if (bone_data > 0x1000) {
                if (read_remote_mem(target_pid, bone_data + OFF_FTransform_Translation,
                                    loc, sizeof(loc)) == 0)
                    pr_info("    Bone[0] Translation = (%f, %f, %f)\n", loc[0], loc[1], loc[2]);
            }
        }
        if (read_remote_mem(target_pid, mesh + OFF_UPrimitiveComponent_LastSubmitTime,
                            &submit_t, sizeof(float)) == 0 &&
            read_remote_mem(target_pid, mesh + OFF_UPrimitiveComponent_LastRenderTime,
                            &render_t, sizeof(float)) == 0)
            pr_info("  LastSubmitTime = %f, LastRenderTime = %f\n", submit_t, render_t);
        if (read_remote_mem(target_pid, mesh + OFF_USceneComponent_ComponentToWorld +
                            OFF_FTransform_Translation, ctw_loc, sizeof(ctw_loc)) == 0)
            pr_info("  ComponentToWorld.Translation = (%f, %f, %f)\n", ctw_loc[0], ctw_loc[1], ctw_loc[2]);
    }

    /* PlayerState */
    if (read_ptr_remote(target_pid, pawn + OFF_ASTExtraPlayerCharacter_to_PlayerState, &playerstate) == 0 &&
        playerstate > 0x1000) {
        read_remote_mem(target_pid, playerstate + OFF_PlayerState_TeamID, &team, sizeof(team));
        read_remote_mem(target_pid, playerstate + OFF_PlayerState_Health, &hp, sizeof(hp));
        read_remote_mem(target_pid, playerstate + OFF_PlayerState_HealthMax, &maxhp, sizeof(maxhp));
        pr_info("PlayerState: TeamID=%d  Health=%.1f/%.1f\n", team, hp, maxhp);

        if (read_ptr_remote(target_pid, playerstate + OFF_PlayerState_PlayerName, &name_data) == 0) {
            read_remote_mem(target_pid, playerstate + OFF_PlayerState_PlayerName + 8,
                            &name_count, sizeof(name_count));
            read_remote_mem(target_pid, playerstate + OFF_PlayerState_PlayerName + 12,
                            &name_max, sizeof(name_max));
            pr_info("  PlayerName: Data=0x%lx Count=%d Max=%d\n", name_data, name_count, name_max);
        }
    }

    pr_info("All checks finished. Look for [OK]/[FAIL] above.\n");
    return -EINVAL;   /* auto‑remove module after test */

chain_fail:
    pr_err("Chain broken – a pointer could not be followed\n");
out:
    return -EFAULT;
}

static void __exit test_exit(void)
{
    pr_info("Module removed\n");
}

module_init(test_offsets);
module_exit(test_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("BGMI offset checker (kernel module)");
