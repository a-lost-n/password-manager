run-client:
	python -m flask --app client_app run --port 5001

run-server:
	python -m flask --app server_app run --port 5002

debug:
	python -m flask run --debug