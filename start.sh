#!/bin/bash
service postgresql start
service redis-server start
sleep 2
systemctl start secos-api
sleep 2
cd /opt/secos/agents
sudo -u secos nohup /opt/secos/venv/bin/python3 agent_siem.py  > /var/log/secos/siem.log  2>&1 &
sudo -u secos nohup /opt/secos/venv/bin/python3 agent_soar.py  > /var/log/secos/soar.log  2>&1 &
sudo -u secos nohup /opt/secos/venv/bin/python3 agent_aegis.py > /var/log/secos/aegis.log 2>&1 &
sudo -u secos nohup /opt/secos/venv/bin/python3 agent_tip.py   > /var/log/secos/tip.log   2>&1 &
nohup /opt/secos/venv/bin/python3 agent_edr.py                 > /var/log/secos/edr.log   2>&1 &
echo "SecOS started — http://localhost:8080"
