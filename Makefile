.PHONY: install uninstall

install:
	pip install .
	sudo cp kernelguard.service /etc/systemd/system/
	sudo systemctl daemon-reload
	@echo "KernelGuard installed. You can now start it with: sudo systemctl start kernelguard"

uninstall:
	sudo systemctl stop kernelguard || true
	sudo systemctl disable kernelguard || true
	sudo rm /etc/systemd/system/kernelguard.service
	sudo systemctl daemon-reload
	pip uninstall -y kernelguard
	@echo "KernelGuard uninstalled."
