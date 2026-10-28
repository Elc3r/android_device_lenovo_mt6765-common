"""Verify filename transitions in an actual binary policy using host checkpolicy."""
from pathlib import Path
import subprocess
import tempfile


def check(policy, checkpolicy):
    with tempfile.TemporaryDirectory(prefix='camera-config-transitions-') as temporary:
        output = Path(temporary) / 'policy.cil'
        subprocess.run([str(checkpolicy), '-b', '-C', '-M', '-o', str(output), str(policy)],
                       capture_output=True, check=True, timeout=30)
        lines = output.read_text().splitlines()
    transitions = {line for line in lines
                   if line.startswith('(typetransition hal_camera_default vendor_camera_config_dir ')}
    expected = {
        '(typetransition hal_camera_default vendor_camera_config_dir file s.json vendor_camera_setting_config)',
        '(typetransition hal_camera_default vendor_camera_config_dir file t.json vendor_camera_tuning_config)',
        '(typetransition hal_camera_default vendor_camera_config_dir file s.h vendor_camera_config_export)',
        '(typetransition hal_camera_default vendor_camera_config_dir file t.h vendor_camera_config_export)',
    }
    if transitions != expected:
        raise ValueError('Unexpected compiled camera configuration transitions: ' + repr(transitions))
    return {'exact_camera_config_filename_transitions': sorted(transitions)}
