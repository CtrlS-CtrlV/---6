/* 
 * sys_tracer.c — власний міні-інструмент трасування та профілювання системних викликів на базі ptrace
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Використання: %s <тестова_програма> [аргументи...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    pid_t child = fork();
    if (child < 0) {
        perror("Помилка fork");
        exit(EXIT_FAILURE);
    }

    if (child == 0) {

        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("Помилка PTRACE_TRACEME");
            exit(EXIT_FAILURE);
        }
        /* Запускаємо цільову програму */
        execvp(argv[1], &argv[1]);
        perror("Помилка execvp");
        exit(EXIT_FAILURE);
    } else {
        /* Батьківський процес (відладник/профайлер) */
        int status;
        long syscall_count = 0;
        int in_syscall = 0;

        printf("=== SYS_TRACER: Запуск моніторингу процесу PID = %d ===\n", child);

        // Очікуємо початкової зупинки дочірнього процесу після exec
        waitpid(child, &status, 0);
        

        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

        while (1) {
            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0) {
                perror("Помилка ptrace PTRACE_SYSCALL");
                break;
            }

            if (waitpid(child, &status, 0) < 0) {
                perror("Помилка waitpid");
                break;
            }

            if (WIFEXITED(status)) {
                printf("\n=== Процес завершився з кодом: %d ===\n", WEXITSTATUS(status));
                break;
            }

            if (WIFSIGNALED(status)) {
                printf("\n=== Процес завершено сигналом: %d ===\n", WTERMSIG(status));
                break;
            }

            if (WIFSTOPPED(status) && (WSTOPSIG(status) & 0x80)) {
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0) {
                    perror("Помилка ptrace PTRACE_GETREGS");
                    break;
                }

                #if defined(__x86_64__)
                unsigned long syscall_num = regs.orig_rax;
                #elif defined(__i386__)
                unsigned long syscall_num = regs.orig_eax;
                #else
                unsigned long syscall_num = regs.rax; // Загальний випадок
                #endif

                if (!in_syscall) {
                    // Вхід у системний виклик
                    syscall_count++;
                    printf("[ТРАСА #%ld] Системний виклик номер (ID): %lu\n", syscall_count, syscall_num);
                    in_syscall = 1;
                } else {
                    // Вихід із системного виклику
                    in_syscall = 0;
                }
            }
        }

        printf("Всього перехоплено системних викликів: %ld\n", syscall_count);
    }

    return 0;
}
