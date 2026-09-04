.PHONY: install uninstall

install:
	sudo mkdir -p /opt/kernelguard
	sudo python3 -m venv --system-site-packages /opt/kernelguard/venv
	sudo /opt/kernelguard/venv/bin/python3 -m pip install .
	sudo cp kernelguard.service /etc/systemd/system/
	sudo systemctl daemon-reload
	@echo "KernelGuard installed. You can now start it with: sudo systemctl start kernelguard"

uninstall:
	sudo systemctl stop kernelguard || true
	sudo systemctl disable kernelguard || true
	sudo rm /etc/systemd/system/kernelguard.service
	sudo rm -rf /opt/kernelguard
	sudo systemctl daemon-reload
	@echo "KernelGuard uninstalled."
