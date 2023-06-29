run-client:
	python -m flask --app client_app run --port 5001

run-server:
	python -m flask --app server_app run --port 5002

run-second-client:
	python -m flask --app client_app run --port 5003

debug:
	python -m flask run --debug