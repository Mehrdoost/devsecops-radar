from flask import Flask

from devsecops_radar.web.sentry.routes import LIVE_FINDINGS, sentry_bp


def create_app():
    app = Flask(__name__)
    app.register_blueprint(sentry_bp)
    return app


class TestSentryAPI:
    @classmethod
    def setup_class(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def setup_method(self):
        LIVE_FINDINGS.clear()

    def test_receive_scan(self):
        data = {"id": "R1", "severity": "HIGH"}
        resp = self.client.post("/scan-result", json=data)
        assert resp.status_code == 200
        assert resp.json == {"status": "received"}
        assert len(LIVE_FINDINGS) == 1
        assert LIVE_FINDINGS[0] == data

    def test_get_live_empty(self):
        resp = self.client.get("/live-findings")
        assert resp.status_code == 200
        assert resp.json == []

    def test_get_live_after_receive(self):
        data1 = {"id": "F1"}
        data2 = {"id": "F2"}
        self.client.post("/scan-result", json=data1)
        self.client.post("/scan-result", json=data2)
        resp = self.client.get("/live-findings")
        assert resp.status_code == 200
        assert resp.json == [data1, data2]
