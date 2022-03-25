def pytest_sessionstart(session):
    # subprocess.call(['sh', './start_infra.sh'])
    # print("Waiting for Keycloak to start")
    # sleep(60)  # Wait for startup
    pass


def pytest_sessionfinish(session):
    # subprocess.call(['sh', './stop_infra.sh'])
    pass
