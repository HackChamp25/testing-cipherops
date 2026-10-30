# Run in GitHub Codespaces

The repository ships a dev container ([`.devcontainer/devcontainer.json`](../.devcontainer/devcontainer.json)), so you
can run CipherOps in the browser with nothing installed locally.

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/aiori-hackathon/A3-PS036-TC161)

## What the dev container sets up

- Python 3.12 with the dashboard requirements installed (`requirements-dashboard.txt`).
- Docker **inside** the codespace (docker-in-docker), so the compose files' bind mounts (`results/`, `configs/`)
  work exactly as they do locally.
- Port 8501 forwarded and labelled "CipherOps dashboard".
- Streamlit settings that the Codespaces port proxy needs (CORS and XSRF protection off, headless), set as
  environment variables inside the codespace only.
- A machine requirement of **4 cores, 16 GB RAM and 32 GB storage**. The offline harness pins itself to core 2 and the
  image builds are large, so a 2-core machine cannot run it.

## Steps

1. Click the badge above (or **Code → Codespaces → Create codespace on the branch**) and choose a **4-core** machine.
2. Wait for the container to finish creating. The first start installs the Python packages.
3. In the terminal, start the dashboard:

   ```bash
   python -m streamlit run dashboard/live_lab/app.py --server.port 8501
   ```

4. Open the forwarded port from the **Ports** tab (or the pop-up) to see the dashboard.
5. **Benchmark → Offline → Quick check** needs nothing else: it builds the pinned image on first use (this can take a
   long time) and then runs. For the lab (**Live**, **Benchmark → Simulated**), build the images in **Setup, step 1**
   first.

From the terminal you can also use the command-line flow in [Getting started](getting-started.md#offline-benchmark-command-line)
and run the tests with `python -m pytest -m "not harness"`.

## Things to know

- **Builds are slow and a codespace stops when idle.** An image build or a full run takes tens of minutes to hours.
  Keep the browser tab open, or raise the idle timeout in your GitHub Codespaces settings. Builds and runs are
  background jobs, so they keep running while the codespace is up.
- **Timings are indicative.** The harness pins a core, but a codespace's virtual CPUs are shared with other tenants. Use
  Codespaces to try the tool and read the byte-level results. For timings you want to report, run on dedicated
  hardware (see [scope and limits](scope-and-limits.md)).
- **Results live in the codespace.** Download `results/runs/<id>/` (right-click, **Download**) before you delete it.
- **Live validation with network emulation** (`scripts/run_live.sh`) needs the `NET_ADMIN` capability for `tc netem`.
  The docker-in-docker daemon allows it, but this has not been confirmed in a codespace.
- **Verification status.** The configuration follows the standard Python plus docker-in-docker template and passes a
  syntax check. A complete first run in a real codespace (image build, offline quick check, dashboard) still needs to
  be confirmed; if something differs, please open an issue.
