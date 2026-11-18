"""Install the opt-in campaign guard on child-process network executables.

Python imports this file automatically only when this repository's scripts
directory is on PYTHONPATH. Normal skill execution has no campaign gate and is
unchanged. In campaign-launched tools, known network executables pass through a
strict adapter or fail closed before the process starts.
"""

import os
import subprocess


if os.environ.get("CATUS_CAMPAIGN_GATE_DB"):
    try:
        from campaign_request_gate import reserve_external_command_from_environment
    except ImportError as error:  # fail closed if campaign mode cannot load its gate
        _campaign_gate_import_error = error

        class CampaignGuardedPopen(subprocess.Popen):
            def __init__(self, *args, **kwargs):
                raise RuntimeError("campaign subprocess gate is unavailable") from _campaign_gate_import_error

    else:
        _OriginalPopen = subprocess.Popen

        class CampaignGuardedPopen(_OriginalPopen):
            def __init__(self, args, *positional, **kwargs):
                safe_args = reserve_external_command_from_environment(
                    args, shell=kwargs.get("shell", False))
                super().__init__(safe_args, *positional, **kwargs)

    subprocess.Popen = CampaignGuardedPopen
