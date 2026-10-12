from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from app.api.deps import get_current_user
from app.models.user import User
from app.bind.tools import (
    execute_dns_query,
    check_global_propagation,
    benchmark_resolvers,
)

router = APIRouter(prefix="/tools", tags=["tools"])


class DigRequest(BaseModel):
    query: str = Field(..., description="Domain name or IP to query")
    rtype: str = Field(default="A", description="DNS record type (A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, ANY)")
    server: str = Field(default="127.0.0.1", description="DNS server to query (127.0.0.1, 1.1.1.1, 8.8.8.8, etc.)")
    port: int = Field(default=53, description="DNS port (default 53)")


class PropagationRequest(BaseModel):
    query: str = Field(..., description="Domain to check propagation across global resolvers")
    rtype: str = Field(default="A", description="DNS record type to check")
    expected_value: str | None = Field(default=None, description="Expected value to match against")


class BenchmarkRequest(BaseModel):
    query: str = Field(default="google.com", description="Domain to query for latency benchmarking")
    rounds: int = Field(default=5, ge=1, le=20, description="Rounds of consecutive queries")


@router.post("/dig")
async def dig_lookup(req: DigRequest, _user: User = Depends(get_current_user)):
    """Execute real DNS query against local BIND or upstream nameservers."""
    try:
        res = execute_dns_query(
            qname=req.query,
            rtype=req.rtype,
            server=req.server,
            port=req.port,
        )
        return {
            "query": res.query,
            "rtype": res.rtype,
            "server": res.server,
            "port": res.port,
            "status": res.status,
            "response_time_ms": res.response_time_ms,
            "flags": res.flags,
            "answers": [
                {"name": a.name, "ttl": a.ttl, "rtype": a.rtype, "rdata": a.rdata}
                for a in res.answers
            ],
            "authority": [
                {"name": a.name, "ttl": a.ttl, "rtype": a.rtype, "rdata": a.rdata}
                for a in res.authority
            ],
            "additional": [
                {"name": a.name, "ttl": a.ttl, "rtype": a.rtype, "rdata": a.rdata}
                for a in res.additional
            ],
            "raw_text": res.raw_text,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/propagation")
async def test_global_propagation(req: PropagationRequest, _user: User = Depends(get_current_user)):
    """Query 8 global public DNS resolvers simultaneously to test record propagation."""
    try:
        results = await check_global_propagation(req.query, req.rtype)
        matched_count = 0
        if req.expected_value:
            exp_clean = req.expected_value.strip().rstrip(".")
            for r in results:
                if any(exp_clean in ans.rstrip(".") for ans in r.get("answers", [])):
                    matched_count += 1
        return {
            "query": req.query,
            "rtype": req.rtype,
            "expected_value": req.expected_value,
            "total_resolvers": len(results),
            "matched_count": matched_count,
            "results": results,
            "resolvers": results,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))



@router.post("/benchmark")
async def test_resolver_benchmark(req: BenchmarkRequest, _user: User = Depends(get_current_user)):
    """Benchmark latency and jitter against Local BIND and major public resolvers."""
    try:
        benchmarks = await benchmark_resolvers(req.query, req.rounds)
        return {"query": req.query, "rounds": req.rounds, "benchmarks": benchmarks}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
