use aperion_shield::predicates::{command_writes, local_command_view};

fn local_writes(cmd: &str) -> bool {
    command_writes(&local_command_view(cmd))
}

#[test]
fn ssh_identity_file_is_not_part_of_the_local_command() {
    let view = local_command_view("ssh -i ~/.ssh/deploy_key root@host uptime");
    assert!(!view.contains(".ssh"), "{view}");
    let view = local_command_view("scp -i ~/.ssh/deploy_key build.tar root@host:/tmp/");
    assert!(!view.contains(".ssh"), "{view}");
    let view = local_command_view("rsync -az -e 'ssh -i ~/.ssh/deploy_key' dist/ root@host:/srv/");
    assert!(!view.contains(".ssh"), "{view}");
}

#[test]
fn remote_command_after_ssh_host_is_dropped() {
    let cmd = "K=~/.ssh/deploy_key; H=root@host; ssh -i $K $H 'install -m 644 /tmp/a.html /var/www/html/ && chown www /var/www/html/a.html && rm /tmp/a.html'";
    assert!(!local_writes(cmd), "{}", local_command_view(cmd));
    assert!(!local_writes("ssh -p 2222 host rm -rf /srv/app"));
}

#[test]
fn local_writes_around_ssh_are_kept() {
    assert!(local_writes("ssh host cat /etc/hosts > ~/.ssh/config"));
    assert!(local_writes("ssh host \"echo $(cp x ~/.ssh/config)\""));
    assert!(local_writes("ssh host uptime; rm ~/.ssh/config"));
    assert!(local_writes("rm ~/.ssh/config"));
}

#[test]
fn commands_without_ssh_are_unchanged() {
    let cmd = "cp a.txt b.txt && ls -la";
    assert_eq!(local_command_view(cmd), cmd);
}
