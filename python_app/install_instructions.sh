# Setup requirements for Ubuntu System Dashboard
# Run this on target Ubuntu server to install dependencies

sudo apt-get update
sudo apt-get install -y python3 python3-pip unzip procps diskspace-info # or other core utils
pip3 install requests 
# (Note: Current server is lightweight and uses only native Python libs like urllib and socket for maximum compatibility and zero failure rates!)

# Copy project files into host path
# sudo cp -r . /home/rpaltaev/dashboard

# Copy and enable systemd service
# sudo cp getipdns.sh /usr/local/bin/getipdns.sh && sudo chmod +x /usr/local/bin/getipdns.sh
# sudo cp python_app/systemd_dashboard.service /etc/systemd/system/dashboard.service
# sudo systemctl daemon-reload
# sudo systemctl enable dashboard.service
# sudo systemctl start dashboard.service
