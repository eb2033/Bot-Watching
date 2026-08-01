FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
	hydra \
	nmap \
	netcat-traditional \
	&& rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
