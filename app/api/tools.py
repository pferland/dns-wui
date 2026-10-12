from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from app.api.deps import get_current_user
from app.models.user import User
from app.bind.tools import execute_dns_query, DigResponse

router = APIRouter(prefix="/tools", tags=["tools"])


class DigRequest(BaseModel):
    query: str = Field(..., description="Domain name or IP to query")
    rtype: str = Field(default="A", description="DNS record type (A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, ANY)")
    server: str = Field(default="127.0.0.1", description="DNS server to query (127.0.0.1, 1.1.1.1, 8.8.8.8, etc.)")
    port: int = Field(default=53, description="DNS port (default 53)")


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
