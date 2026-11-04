import pytest
from httpx import AsyncClient, ASGITransport
from backend.app.main import app

@pytest.fixture
def anyio_backend():
    return 'asyncio'

@pytest.mark.anyio
async def test_threats_summary():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/threats/summary")
        assert res.status_code == 200
        data = res.json()
        assert "total" in data
        assert "critical" in data
        assert "high" in data
        assert "medium" in data
        assert "low" in data
        assert data["total"] > 0

@pytest.mark.anyio
async def test_threats_pagination():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/threats?page=1&limit=10")
        assert res.status_code == 200
        data = res.json()
        assert "items" in data
        assert len(data["items"]) <= 10
        assert data["total"] > 0
        assert data["page"] == 1

@pytest.mark.anyio
async def test_threats_exclude_normal_filter():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/threats?exclude_normal=true&limit=25")
        assert res.status_code == 200
        items = res.json().get("items", [])
        for item in items:
            assert item["attack_type"].lower() not in ["benign", "normal"]

@pytest.mark.anyio
async def test_threats_map_vectors():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/threats/map")
        assert res.status_code == 200
        points = res.json()
        assert isinstance(points, list)
        for pt in points:
            assert pt["lat"] is not None
            assert pt["lon"] is not None
            assert pt["attack_type"].lower() not in ["benign", "normal"]

@pytest.mark.anyio
async def test_model_metrics_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/model/metrics")
        assert res.status_code == 200
        data = res.json()
        assert "accuracy" in data
        assert "macro_f1" in data
        assert "benchmark_comparison" in data
        assert len(data["benchmark_comparison"]) >= 4

@pytest.mark.anyio
async def test_threat_detail_and_containment_rules():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Fetch one threat
        list_res = await client.get("/threats?limit=1")
        items = list_res.json().get("items", [])
        assert len(items) > 0
        threat_id = items[0]["id"]

        # Detail
        detail_res = await client.get(f"/threats/{threat_id}")
        assert detail_res.status_code == 200
        assert detail_res.json()["id"] == threat_id

        # Containment rules
        rules_res = await client.get(f"/threats/{threat_id}/rules")
        assert rules_res.status_code == 200
        rules = rules_res.json()
        assert "windows_netsh" in rules
        assert "linux_iptables" in rules
        assert "suricata_rule" in rules

@pytest.mark.anyio
async def test_threat_report_pdf():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        list_res = await client.get("/threats?limit=1")
        threat_id = list_res.json()["items"][0]["id"]

        res = await client.get(f"/threats/{threat_id}/report/pdf")
        assert res.status_code == 200
        assert res.headers["content-type"] == "application/pdf"
        assert len(res.content) > 1000
