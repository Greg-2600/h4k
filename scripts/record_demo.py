"""Record docs/img/demo.gif: scripted walkthrough of the kill-chain console.

Spins a sandbox API (no network, no daemon), seeds the lab estate, drives
the real UI through Discover -> Recon -> Exploit -> Score and assembles the
screenshots into a GIF with ffmpeg.

Usage: python3 scripts/record_demo.py  (needs chromium + ffmpeg on PATH)
"""

import json
import os
import subprocess
import sys
import time
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_PKG = os.path.join(REPO, "h4k", "api")
SHOTS = "/tmp/h4k-demo-shots"


def api(base, method, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode() or "{}")


def main():
    port = 3140
    env = dict(os.environ)
    env.update(
        {
            "H4K_SANDBOX": "1",
            "H4K_DATA_DIR": "/tmp/h4k-demo-data",
            "H4K_REFRESH_CVE": "0",
            "H4K_AUTO_SCAN": "0",
            "PYTHONPATH": API_PKG + os.pathsep + env.get("PYTHONPATH", ""),
        }
    )
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1",
         "--port", str(port)],
        cwd=API_PKG, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(30):
            try:
                api(base, "GET", "/api/health")
                break
            except OSError:
                time.sleep(1)
        eng = api(base, "POST", "/api/engagement/sandbox-seed")["engagement"]
        api(base, "POST", "/api/session/scope", {"engagement_id": eng["id"]})
        print("seeded", eng["id"], flush=True)

        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.support.ui import WebDriverWait

        opts = Options()
        opts.add_argument("--headless=new")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--window-size=1280,800")
        opts.add_argument("--disable-dev-shm-usage")
        for var in ("H4K_CHROME_BINARY", "CHROME_BINARY"):
            if os.environ.get(var):
                opts.binary_location = os.environ[var]
                break
        else:
            import shutil
            for candidate in ("chromium", "google-chrome", "chromium-browser"):
                found = shutil.which(candidate)
                if found:
                    opts.binary_location = found
                    break
        driver = webdriver.Chrome(options=opts)
        wait = WebDriverWait(driver, 30)
        os.makedirs(SHOTS, exist_ok=True)

        def shot(name, tab=None, setup=None):
            if tab:
                driver.find_element(By.CSS_SELECTOR, f'.ws-btn[data-tab="{tab}"]').click()
                time.sleep(1.5)
            if setup:
                setup()
                time.sleep(1.5)
            driver.save_screenshot(os.path.join(SHOTS, f"{name}.png"))
            print("shot", name, flush=True)

        driver.get(base + "/")
        wait.until(EC.presence_of_element_located((By.ID, "target")))
        time.sleep(4)  # status pills + next-move settle

        shot("01-discover")
        shot("02-neighbors", "discover",
             lambda: driver.find_element(By.CSS_SELECTOR, '[data-testid="btn-neighbors"]').click() or time.sleep(6))
        shot("03-fingerprint", "recon",
             lambda: driver.find_element(By.CSS_SELECTOR, '[data-testid="btn-fingerprint"]').click() or time.sleep(6))
        shot("04-exploit", "exploit")
        shot("05-paths", "score",
             lambda: driver.find_element(By.CSS_SELECTOR, '[data-testid="compute-paths"]').click() or time.sleep(3))
        driver.quit()
    finally:
        server.terminate()

    frames = sorted(
        os.path.join(SHOTS, f) for f in os.listdir(SHOTS) if f.endswith(".png")
    )
    with open("/tmp/h4k-demo-list.txt", "w") as fh:
        for _ in range(2):  # hold the first frame a beat longer
            fh.write(f"file '{frames[0]}'\nduration 2.5\n")
        for f in frames[1:]:
            fh.write(f"file '{f}'\nduration 2.5\n")
        fh.write(f"file '{frames[-1]}'\n")
    out = os.path.join(REPO, "docs", "img", "demo.gif")
    subprocess.run(
        ["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", "/tmp/h4k-demo-list.txt",
         "-vf", "scale=1280:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=128[p];[s1][p]paletteuse",
         "-r", "2", out],
        check=True,
    )
    print("wrote", out, os.path.getsize(out), "bytes")


if __name__ == "__main__":
    main()
