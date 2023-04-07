#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

static pid_t runagent(char *agent_cmd[], const char *pid_env);
static int runcmd(char *cmd_args[], char **pout);

static pid_t ssh_agent_pid = 0;

void
cleanagent(void)
{
	if (ssh_agent_pid)
		kill(ssh_agent_pid, SIGTERM);
}

static pid_t
runagent(char *agent_cmd[], const char *pid_env)
{
	fprintf(stderr, "run agent %s\n", agent_cmd[0]);
	char *output;
	if (runcmd(agent_cmd, &output)) {
		return 0;
	}
	pid_t agent_pid = 0;
	const char *sep = "; \r\n\t";
	char *s = output;
	while (s && *s) {
		char *expr = s;
		s = strpbrk(s, sep);
		if (s) {
			int n = strspn(s, sep);
			*s = 0;
			s = s + n;
		}
		if (*expr == '#')
			continue;
		char *val = strchr(expr, '=');
		if (!val)
			continue;
		*val++ = 0;
		setenv(expr, val, 1);
		if (!strcmp(expr, pid_env))
			agent_pid = atoi(val);
	}
	free(output);
	return agent_pid;
}

static int
runcmd(char *cmd_args[], char **pout)
{
	int pipefd[2];
	if (pipe(pipefd) < 0)
		return 1;
	pid_t child = fork();
	if (child < 0)
		return 1;
	if (child == 0) {
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[1]);
		execv(cmd_args[0], (char **)cmd_args);
		exit(0);
	}

	close(pipefd[1]);
	int cap = 256;
	char *outbuf = malloc(cap);
	int len = 0;
	#define MAX_OUTBUF_SIZE (1<<20)
	while (len < MAX_OUTBUF_SIZE) {
		int n = read(pipefd[0], outbuf + len, cap - len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (n == 0)
			break;
		len += n;
		if (len == cap) {
			cap += cap > 4096 ? 4096 : cap;
			outbuf = realloc(outbuf, cap);
		}
	}
	close(pipefd[0]);
	outbuf[len] = 0;

	int status = 0;
	wait(&status);

	if (status)
		free(outbuf);
	else
		*pout = outbuf;

	return status;
}

void
startagent(void)
{
	char *ssh_agent_cmd[] = { "/usr/bin/ssh-agent", "-s", NULL };
	if (!access(ssh_agent_cmd[0], X_OK)) {
		ssh_agent_pid = runagent(ssh_agent_cmd, "SSH_AGENT_PID");
		if (ssh_agent_pid > 0) {
			// see: https://github.com/xfce-mirror/xfce4-session/blob/xfce-4.16/xfce4-session/xfsm-startup.c#L305
			if (!access("/run/systemd/seats/", F_OK))
				system("dbus-update-activation-environment --systemd SSH_AUTH_SOCK");
			else
				system("dbus-update-activation-environment SSH_AUTH_SOCK");
		}
	} else {
		fprintf(stderr, "no ssh-agent executable\n");
	}
}
