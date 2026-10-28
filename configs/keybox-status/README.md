# Optional keybox boot status

The selected rc preserves the original helper command, service identity, groups
and oneshot definition, adding only `disabled` for the automatic optional probe.
It neither provisions keys nor fabricates success/status. No TEE grant is added.
Manual secure-world commands are not part of the build or update workflow.
