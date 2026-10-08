FROM postgres:16.15

COPY certs/dbServer.crt /var/lib/postgresql/certs/dbServer.crt
COPY certs/dbServer.key /var/lib/postgresql/certs/dbServer.key

RUN chown postgres:postgres /var/lib/postgresql/certs/dbServer.crt /var/lib/postgresql/certs/dbServer.key \
	&& chmod 644 /var/lib/postgresql/certs/dbServer.crt \
	&& chmod 600 /var/lib/postgresql/certs/dbServer.key
