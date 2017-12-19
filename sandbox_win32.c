#include "sandbox.h"
#include <windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "Psapi.lib")

#define PROCESS_CLOSE() do {CloseHandle(hChildStdinRd); CloseHandle(hChildStdoutRd); CloseHandle(hChildStderrRd); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);} while(0);

long long ftime_to_ll(const FILETIME *ft) {
	return ft->dwLowDateTime + ((long long)ft->dwHighDateTime << 32);
}

sandbox_result_t sandbox_run(const sandbox_config_t *cfg) {
	sandbox_result_t result;
	result.verdict = ER_FAIL;
	result.exit_code = 0;
	result.cpu_time = 0;
	result.mem_usage = 0;
	result.s_stdout = NULL;
	result.s_stderr = NULL;
	
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	SECURITY_ATTRIBUTES sa;
	
	ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&sa, sizeof(sa));
	
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;
	
	HANDLE hChildStdinRd, hChildStdinWr, hChildStdoutRd, hChildStdoutWr, hChildStderrRd, hChildStderrWr;

	if (!CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &sa, 0)) {
		return result;
	}

	if (!CreatePipe(&hChildStdinRd, &hChildStdinWr, &sa, 0)) {
		CloseHandle(hChildStdoutRd);
		CloseHandle(hChildStdoutWr);
		return result;
	}
	
	if (!CreatePipe(&hChildStderrRd, &hChildStderrWr, &sa, 0)) {
		CloseHandle(hChildStdinRd);
		CloseHandle(hChildStdinWr);
		CloseHandle(hChildStdoutRd);
		CloseHandle(hChildStdoutWr);
		return result;
	}
	
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdError = hChildStderrWr;
    si.hStdOutput = hChildStdoutWr;
    si.hStdInput = hChildStdinRd;
	
	if (!CreateProcess(cfg->path, NULL, NULL, NULL, true, CREATE_NO_WINDOW | DEBUG_PROCESS, NULL, NULL, &si, &pi)) {
		if (cfg->debug) {
			fprintf(stderr, "(sandbox) CreateProcess failed\n");
		}
	} else {
		DWORD written;
        BOOL ok;
        // Write terminating zero to make EOF
        ok = WriteFile(hChildStdinWr, cfg->s_stdin, strlen(cfg->s_stdin) + 1, &written, NULL);
        CloseHandle(hChildStdoutWr);
		CloseHandle(hChildStderrWr);
        CloseHandle(hChildStdinWr);
        if (!ok || written <= strlen(cfg->s_stdin)) {
            PROCESS_CLOSE();
            return result;
        }
		
		DEBUG_EVENT de;
		int proc = 0;
		bool good = true;
		while (good) {
			if (WaitForDebugEvent(&de, cfg->time_limit)) {
				switch (de.dwDebugEventCode) {
					case EXCEPTION_DEBUG_EVENT:
						if (!de.u.Exception.dwFirstChance) {
							if (cfg->debug) {
								fprintf(stderr, "(sandbox) Exception\n");
							}
							result.verdict = ER_RT;
							good = false;
						}
						break;
						
					case CREATE_THREAD_DEBUG_EVENT:
						if (cfg->debug) {
							fprintf(stderr, "(sandbox) Created thread\n");
						}
						CloseHandle(de.u.CreateThread.hThread);
						//result.verdict = ER_SE;
						//good = false;
						break;
						
					case CREATE_PROCESS_DEBUG_EVENT:
						if (cfg->debug) {
							fprintf(stderr, "(sandbox) Created process\n");
						}
						CloseHandle(de.u.CreateProcessInfo.hFile);
						proc++;
						if (proc > 1) {
							result.verdict = ER_SE;
							good = false;
						}
						break;
					
					case EXIT_THREAD_DEBUG_EVENT:
						break;
					
					case EXIT_PROCESS_DEBUG_EVENT:
						proc--;
						if (proc == 0) {
							if (cfg->debug) {
								fprintf(stderr, "(sandbox) Exited\n");
							}
							result.verdict = ER_OK;
							good = false;
						}
						break;
					
					case LOAD_DLL_DEBUG_EVENT:
						CloseHandle(de.u.LoadDll.hFile);
						break;
					
					case UNLOAD_DLL_DEBUG_EVENT:
						break;
					case OUTPUT_DEBUG_STRING_EVENT:
						break;
					case RIP_EVENT:
						if (cfg->debug) {
							fprintf(stderr, "(sandbox) RIP_EVENT\n");
						}
						result.verdict = ER_FAIL;
						good = false;
						break;
				}
				if (good)
					ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
			}
			
			FILETIME create, exit, kernel, user;
			if (GetProcessTimes(pi.hProcess, &create, &exit, &kernel, &user)) {
				long long time = ftime_to_ll(&kernel) + ftime_to_ll(&user);
				result.cpu_time = time / 10000;
				if (result.cpu_time > cfg->time_limit) {
					result.verdict = ER_TL;
					good = false;
				}
				
				SYSTEMTIME st;
                GetSystemTime(&st);
                if (SystemTimeToFileTime(&st, &exit)) {
                    time = ftime_to_ll(&exit) - ftime_to_ll(&create);
                    if (time / 10000 > cfg->wall_time_limit) {
                        result.verdict = ER_WT;
						good = false;
					}
                } else {
					if (cfg->debug) {
						fprintf(stderr, "(sandbox) SystemTimeToFileTime failed\n");
					}
					result.verdict = ER_FAIL;
					good = false;
				}
			} else {
				if (cfg->debug) {
					fprintf(stderr, "(sandbox) GetProcessTimes failed\n");
				}
				result.verdict = ER_FAIL;
				good = false;
			}
			
			PROCESS_MEMORY_COUNTERS mem;
            if (GetProcessMemoryInfo(pi.hProcess, &mem, sizeof(mem))) {
				result.mem_usage = mem.PeakWorkingSetSize;
                if (result.mem_usage > cfg->mem_limit) {
                    result.verdict = ER_ML;
					good = false;
				}
            } else {
				if (cfg->debug) {
					fprintf(stderr, "(sandbox) GetProcessMemoryInfo failed\n");
				}
				result.verdict = ER_FAIL;
				good = false;
			}
		}
		
		if (cfg->debug) {
			fprintf(stderr, "(sandbox) process finished. cpu_time = %ld ms, mem_usage = %ld bytes\n", result.cpu_time, result.mem_usage);
		}
		
		if (result.verdict != ER_OK) {
			if (cfg->debug) {
				TerminateProcess(pi.hProcess, 0);
				PROCESS_CLOSE();
			}
		} else {
			DWORD exit_code = 0;
			if (!GetExitCodeProcess(pi.hProcess, &exit_code)) {
				if (cfg->debug) {
					fprintf(stderr, "(sandbox) GetExitCodeProcess failed\n");
				}
				PROCESS_CLOSE();
				result.verdict = ER_FAIL;
			} else {
				if (cfg->debug) {
					fprintf(stderr, "(sandbox) exit code = %d\n", exit_code);
				}
				result.exit_code = exit_code;
				if (result.exit_code != 0) {
					result.verdict = ER_RT;
					PROCESS_CLOSE();
				} else {
					char *pstdout = malloc(1);
					char *pstderr = malloc(1);
					pstdout[0] = (char)0;
					pstderr[0] = (char)0;
					int wstdout = 1;
					int wstderr = 1;
					
					for (;;) {
						DWORD read;
						BOOL success = PeekNamedPipe(hChildStdoutRd, NULL, 0, NULL, &read, NULL);
						if (!success || read == 0)
							break;
							
						char buffer[128];
						success = ReadFile(hChildStdoutRd, buffer, sizeof(buffer) - 1, &read, NULL);
						wstdout += read;
						if (!success || read == 0)
							break;
						buffer[read] = 0;
						char *tmp = realloc(pstdout, wstdout);
						if (tmp) {
							pstdout = tmp;
						} else {
							fprintf(stderr, "(sandbox) realloc() failed\n");
							PROCESS_CLOSE();
							result.verdict = ER_FAIL;
							return result;
						}
						strncat(pstdout, buffer, read);
					}
					
					for (;;) {
						DWORD read;
						BOOL success = PeekNamedPipe(hChildStderrRd, NULL, 0, NULL, &read, NULL);
						if (!success || read == 0)
							break;
							
						char buffer[128];
						success = ReadFile(hChildStderrRd, buffer, sizeof(buffer) - 1, &read, NULL);
						wstderr += read;
						if (!success || read == 0)
							break;
						buffer[read] = 0;
						char *tmp = realloc(pstderr, wstderr);
						if (tmp) {
							pstderr = tmp;
						} else {
							fprintf(stderr, "(sandbox) realloc() failed\n");
							PROCESS_CLOSE();
							result.verdict = ER_FAIL;
							return result;
						}
						strncat(pstderr, buffer, read);
					}
					
					result.s_stdout = pstdout;
					result.s_stderr = pstderr;
					PROCESS_CLOSE();
				}
			}
		}
	}
	
	if (cfg->debug) {
		switch (result.verdict) {
			case ER_OK: fprintf(stderr, "(sandbox) verdict: ok.\n"); break;
			case ER_TL: fprintf(stderr, "(sandbox) verdict: time limit exceeded. TL = %ld ms\n", cfg->time_limit); break;
			case ER_ML: fprintf(stderr, "(sandbox) verdict: memory limit exeeded. ML = %ld bytes\n", cfg->mem_limit); break;
			case ER_RT: fprintf(stderr, "(sandbox) verdict: runtime error. EXITCODE = %d\n", result.exit_code); break;
			case ER_WT: fprintf(stderr, "(sandbox) verdict: wall time limit exceeded. WT = %ld ms\n", cfg->wall_time_limit); break;
			case ER_SE: fprintf(stderr, "(sandbox) verdict: security violation\n"); break;
			case ER_FAIL: fprintf(stderr, "(sandbox) verdict: fail\n"); break;
		}
	}
	
	return result;
}