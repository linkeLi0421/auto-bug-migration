import json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()/"script"))
from script.react_agent.tools.ossfuzz_tools import merge_patch_bundle_with_overrides

run = Path("data/react_agent_artifacts/multi_20260116_162632_2769396_aa9b35f6").resolve()
s = json.loads((run/"summary.json").read_text())
os.environ["REACT_AGENT_ARTIFACT_ROOT"] = str(run)  # output + “allowed root” for override paths

out = merge_patch_bundle_with_overrides(
    patch_path=s["patch_path"],
    patch_override_paths=s["final_ossfuzz_test"]["override_paths"],
    output_name="debug_merged.diff",
)
print(out)  # check override_count / overridden_patch_keys / merged_patch_file_path