import os
import json
import time
import logging
from typing import List, Dict, Any, Optional

from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Text, Boolean, DateTime, ForeignKey
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session

logger = logging.getLogger("sentinel.database")

Base = declarative_base()

# =========================================================================
# 1. DATABASE MODELS
# =========================================================================

class CaseModel(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False, default="Autonomous Cyber Incident Investigation")
    status = Column(String(32), nullable=False, default="INVESTIGATING")
    created_at = Column(String(64), nullable=False)
    updated_at = Column(String(64), nullable=False)
    risk_score = Column(Float, default=0.0)
    risk_rating = Column(String(32), default="INFORMATIONAL")
    confidence_score = Column(Float, default=0.0)
    summary = Column(Text, nullable=True)

    evidence_items = relationship("EvidenceModel", backref="case", cascade="all, delete-orphan")
    iocs = relationship("IOCModel", backref="case", cascade="all, delete-orphan")
    steps = relationship("InvestigationStepModel", backref="case", cascade="all, delete-orphan")
    leads = relationship("LeadModel", backref="case", cascade="all, delete-orphan")
    hypotheses = relationship("HypothesisModel", backref="case", cascade="all, delete-orphan")
    graph_entities = relationship("GraphEntityModel", backref="case", cascade="all, delete-orphan")
    graph_relationships = relationship("GraphRelationshipModel", backref="case", cascade="all, delete-orphan")
    threat_intel_results = relationship("ThreatIntelResultModel", backref="case", cascade="all, delete-orphan")
    reports = relationship("ReportModel", backref="case", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLogModel", backref="case", cascade="all, delete-orphan")

class EvidenceModel(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False)
    source_file = Column(String(255), nullable=False)
    source_type = Column(String(64), nullable=False)
    event_type = Column(String(64), nullable=False)
    timestamp = Column(String(64), nullable=False)
    raw_reference = Column(Text, nullable=True)
    normalized_data = Column(Text, nullable=True)
    provenance = Column(Text, nullable=True)

class IOCModel(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False)
    indicator = Column(String(255), nullable=False)
    indicator_type = Column(String(64), nullable=False)
    source = Column(String(128), nullable=True)
    first_seen = Column(String(64), nullable=True)
    last_seen = Column(String(64), nullable=True)
    confidence = Column(Float, default=1.0)

class InvestigationStepModel(Base):
    __tablename__ = "investigation_steps"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False)
    step_number = Column(Integer, nullable=False)
    tool_name = Column(String(128), nullable=False)
    query = Column(Text, nullable=True)
    rationale = Column(Text, nullable=True)
    result_summary = Column(Text, nullable=True)
    provider = Column(String(64), nullable=False, default="fallback")
    model = Column(String(128), nullable=False, default="deterministic-planner")
    llm_used = Column(Boolean, default=False)
    fallback_occurred = Column(Boolean, default=True)
    timestamp = Column(String(64), nullable=False)

class LeadModel(Base):
    __tablename__ = "leads"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False)
    lead = Column(Text, nullable=False)
    lead_type = Column(String(64), nullable=False)
    priority = Column(String(32), default="HIGH")
    status = Column(String(32), default="UNANSWERED")
    source = Column(String(128), nullable=True)
    created_at = Column(String(64), nullable=False)

class HypothesisModel(Base):
    __tablename__ = "hypotheses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False)
    hypothesis = Column(Text, nullable=False)
    confidence = Column(Float, default=0.0)
    supporting_evidence = Column(Text, nullable=True)
    contradicting_evidence = Column(Text, nullable=True)
    status = Column(String(32), default="ACTIVE")

class GraphEntityModel(Base):
    __tablename__ = "graph_entities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False)
    entity = Column(String(255), nullable=False)
    entity_type = Column(String(64), nullable=False)
    properties = Column(Text, nullable=True)

class GraphRelationshipModel(Base):
    __tablename__ = "graph_relationships"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False)
    source_entity = Column(String(255), nullable=False)
    relationship = Column(String(128), nullable=False)
    target_entity = Column(String(255), nullable=False)
    confidence = Column(Float, default=1.0)

class ThreatIntelResultModel(Base):
    __tablename__ = "threat_intel_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False)
    indicator = Column(String(255), nullable=False)
    indicator_type = Column(String(64), nullable=False)
    provider = Column(String(64), default="VirusTotal/WHOIS")
    result = Column(Text, nullable=True)
    timestamp = Column(String(64), nullable=False)

class ReportModel(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False)
    report_data = Column(Text, nullable=False)
    created_at = Column(String(64), nullable=False)

class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False)
    action = Column(String(128), nullable=False)
    actor = Column(String(128), default="AUTONOMOUS_AGENT")
    details = Column(Text, nullable=True)
    timestamp = Column(String(64), nullable=False)


# =========================================================================
# 2. ENGINE & SESSION INITIALIZATION (PostgreSQL with SQLite Fallback)
# =========================================================================

DEFAULT_SQLITE_URL = "sqlite:///sentinel.db"

def get_engine():
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        logger.info("DATABASE_URL not set. Falling back to local SQLite database (sentinel.db).")
        db_url = DEFAULT_SQLITE_URL

    connect_args = {}
    if db_url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}

    try:
        engine = create_engine(db_url, connect_args=connect_args, pool_pre_ping=True)
        with engine.connect() as conn:
            pass
        return engine, db_url
    except Exception as e:
        logger.warning(f"Failed to connect to primary DATABASE_URL '{db_url}': {e}. Falling back to SQLite.")
        fallback_engine = create_engine(DEFAULT_SQLITE_URL, connect_args={"check_same_thread": False})
        return fallback_engine, DEFAULT_SQLITE_URL

engine, ACTIVE_DB_URL = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Initializes tables safely on startup."""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info(f"Database schema initialized cleanly on '{ACTIVE_DB_URL}'.")
    except Exception as e:
        logger.error(f"Error creating database tables: {e}")

# Call init_db on module import
init_db()


# =========================================================================
# 3. HIGH-LEVEL PERSISTENCE HELPER FUNCTIONS
# =========================================================================

def save_case_to_db(case_dict: Dict[str, Any]) -> None:
    """
    Saves or updates complete case state into persistent storage.
    """
    session: Session = SessionLocal()
    try:
        case_id = case_dict.get("case_id", "CASE-UNKNOWN")
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")

        existing_case = session.query(CaseModel).filter_by(case_id=case_id).first()
        if not existing_case:
            existing_case = CaseModel(
                case_id=case_id,
                title=f"Incident Case {case_id}",
                status=case_dict.get("status", "INVESTIGATING"),
                created_at=now_str,
                updated_at=now_str,
                risk_score=float(case_dict.get("risk_score", 0.0)),
                risk_rating=case_dict.get("risk_rating", "INFORMATIONAL"),
                confidence_score=float(case_dict.get("confidence_score", 0.0)),
                summary=str(case_dict.get("summary", ""))
            )
            session.add(existing_case)
        else:
            existing_case.status = case_dict.get("status", existing_case.status)
            existing_case.updated_at = now_str
            existing_case.risk_score = float(case_dict.get("risk_score", existing_case.risk_score))
            existing_case.risk_rating = case_dict.get("risk_rating", existing_case.risk_rating)
            existing_case.confidence_score = float(case_dict.get("confidence_score", existing_case.confidence_score))
            existing_case.summary = str(case_dict.get("summary", existing_case.summary))

        session.commit()

        # 1. Save Evidence
        for ev in case_dict.get("events", []):
            ev_source = ev.get("source_file", "Ingested Log")
            existing_ev = session.query(EvidenceModel).filter_by(
                case_id=case_id,
                raw_reference=str(ev)
            ).first()
            if not existing_ev:
                session.add(EvidenceModel(
                    case_id=case_id,
                    source_file=ev_source,
                    source_type=ev.get("source_type", "LOG"),
                    event_type=ev.get("event_type", "GENERIC_EVENT"),
                    timestamp=ev.get("timestamp", now_str),
                    raw_reference=str(ev),
                    normalized_data=json.dumps(ev),
                    provenance=ev.get("provenance", "Log Ingestion Pipeline")
                ))

        # 2. Save IOCs
        for ioc in case_dict.get("iocs", []):
            val = ioc.get("value") if isinstance(ioc, dict) else str(ioc)
            itype = ioc.get("type", "UNKNOWN") if isinstance(ioc, dict) else "UNKNOWN"
            existing_ioc = session.query(IOCModel).filter_by(case_id=case_id, indicator=val).first()
            if not existing_ioc:
                session.add(IOCModel(
                    case_id=case_id,
                    indicator=val,
                    indicator_type=itype,
                    source="Evidence Normalizer",
                    first_seen=now_str,
                    last_seen=now_str,
                    confidence=1.0
                ))

        # 3. Save Leads
        for l in case_dict.get("leads", []):
            lid = l.get("id") if isinstance(l, dict) else str(l)
            lead_text = l.get("question", str(l)) if isinstance(l, dict) else str(l)
            ltype = l.get("ioc_type", "GENERAL") if isinstance(l, dict) else "GENERAL"
            lstatus = l.get("status", "UNANSWERED") if isinstance(l, dict) else "UNANSWERED"
            existing_lead = session.query(LeadModel).filter_by(case_id=case_id, lead=lead_text).first()
            if not existing_lead:
                session.add(LeadModel(
                    case_id=case_id,
                    lead=lead_text,
                    lead_type=ltype,
                    priority="HIGH",
                    status=lstatus,
                    source="Lead Generator",
                    created_at=now_str
                ))
            else:
                existing_lead.status = lstatus

        # 4. Save Hypotheses
        for h in case_dict.get("hypotheses", []):
            htitle = h.get("title", h.get("hypothesis", str(h))) if isinstance(h, dict) else str(h)
            hscore = float(h.get("score", h.get("confidence", 0.0))) if isinstance(h, dict) else 0.0
            existing_h = session.query(HypothesisModel).filter_by(case_id=case_id, hypothesis=htitle).first()
            if not existing_h:
                session.add(HypothesisModel(
                    case_id=case_id,
                    hypothesis=htitle,
                    confidence=hscore,
                    supporting_evidence=json.dumps(h.get("supporting_evidence", [])) if isinstance(h, dict) else None,
                    contradicting_evidence=json.dumps(h.get("contradicting_evidence", [])) if isinstance(h, dict) else None,
                    status="ACTIVE"
                ))
            else:
                existing_h.confidence = hscore

        # 5. Save Graph Entities & Relationships
        graph_summary = case_dict.get("graph_summary", {})
        for node in graph_summary.get("nodes", []):
            nval = node.get("id", str(node)) if isinstance(node, dict) else str(node)
            ntype = node.get("type", "ENTITY") if isinstance(node, dict) else "ENTITY"
            existing_node = session.query(GraphEntityModel).filter_by(case_id=case_id, entity=nval).first()
            if not existing_node:
                session.add(GraphEntityModel(
                    case_id=case_id,
                    entity=nval,
                    entity_type=ntype,
                    properties=json.dumps(node) if isinstance(node, dict) else None
                ))

        for edge in graph_summary.get("edges", []):
            src = edge.get("source", "")
            rel = edge.get("relation", "CONNECTED_TO")
            tgt = edge.get("target", "")
            if src and tgt:
                existing_edge = session.query(GraphRelationshipModel).filter_by(
                    case_id=case_id, source_entity=src, target_entity=tgt, relationship=rel
                ).first()
                if not existing_edge:
                    session.add(GraphRelationshipModel(
                        case_id=case_id,
                        source_entity=src,
                        relationship=rel,
                        target_entity=tgt,
                        confidence=1.0
                    ))

        # 6. Save Audit Trail Steps
        for step in case_dict.get("audit_trail", []):
            s_num = step.get("step", 0)
            existing_step = session.query(InvestigationStepModel).filter_by(case_id=case_id, step_number=s_num).first()
            if not existing_step:
                session.add(InvestigationStepModel(
                    case_id=case_id,
                    step_number=s_num,
                    tool_name=step.get("tool_called", "unknown"),
                    query=json.dumps(step.get("tool_args", {})),
                    rationale=step.get("rationale", ""),
                    result_summary=step.get("findings", ""),
                    provider=step.get("llm_provider", "fallback"),
                    model=step.get("llm_model", "deterministic-planner"),
                    llm_used=bool(step.get("llm_used", False)),
                    fallback_occurred=bool(step.get("fallback_occurred", True)),
                    timestamp=step.get("timestamp", now_str)
                ))
                session.add(AuditLogModel(
                    case_id=case_id,
                    action=f"EXECUTED_TOOL:{step.get('tool_called')}",
                    actor=step.get("llm_provider", "fallback"),
                    details=json.dumps(step),
                    timestamp=step.get("timestamp", now_str)
                ))

        # 7. Save Report if available
        if case_dict.get("report"):
            rep_str = json.dumps(case_dict["report"])
            existing_rep = session.query(ReportModel).filter_by(case_id=case_id).first()
            if not existing_rep:
                session.add(ReportModel(
                    case_id=case_id,
                    report_data=rep_str,
                    created_at=now_str
                ))
            else:
                existing_rep.report_data = rep_str

        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Error persisting case to DB: {e}")
    finally:
        session.close()

def save_investigation_step_to_db(case_id: str, step_data: Dict[str, Any]) -> None:
    """
    Saves an individual investigation step to the database immediately.
    """
    session: Session = SessionLocal()
    try:
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        s_num = step_data.get("step", 0)

        existing = session.query(InvestigationStepModel).filter_by(case_id=case_id, step_number=s_num).first()
        if not existing:
            session.add(InvestigationStepModel(
                case_id=case_id,
                step_number=s_num,
                tool_name=step_data.get("tool_called", "unknown"),
                query=json.dumps(step_data.get("tool_args", {})),
                rationale=step_data.get("rationale", ""),
                result_summary=step_data.get("findings", ""),
                provider=step_data.get("llm_provider", "fallback"),
                model=step_data.get("llm_model", "deterministic-planner"),
                llm_used=bool(step_data.get("llm_used", False)),
                fallback_occurred=bool(step_data.get("fallback_occurred", True)),
                timestamp=step_data.get("timestamp", now_str)
            ))
            session.add(AuditLogModel(
                case_id=case_id,
                action=f"EXECUTED_TOOL:{step_data.get('tool_called')}",
                actor=step_data.get("llm_provider", "fallback"),
                details=json.dumps(step_data),
                timestamp=step_data.get("timestamp", now_str)
            ))
            session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to persist investigation step: {e}")
    finally:
        session.close()

def load_case_from_db(case_id: str) -> Optional[Dict[str, Any]]:
    """
    Loads complete investigation case state from database by case_id.
    """
    session: Session = SessionLocal()
    try:
        c_record = session.query(CaseModel).filter_by(case_id=case_id).first()
        if not c_record:
            return None

        # Load Evidence
        events = []
        for ev in session.query(EvidenceModel).filter_by(case_id=case_id).all():
            if ev.normalized_data:
                try:
                    events.append(json.loads(ev.normalized_data))
                except Exception:
                    pass

        # Load IOCs
        iocs = []
        for i in session.query(IOCModel).filter_by(case_id=case_id).all():
            iocs.append({"value": i.indicator, "type": i.indicator_type})

        # Load Leads
        leads = []
        for idx, l in enumerate(session.query(LeadModel).filter_by(case_id=case_id).all(), 1):
            leads.append({
                "id": f"LEAD-{idx:03d}",
                "question": l.lead,
                "target_ioc": l.lead.split()[-1] if l.lead else "UNKNOWN",
                "ioc_type": l.lead_type,
                "status": l.status,
                "findings": ""
            })

        # Load Hypotheses
        hypotheses = []
        for h in session.query(HypothesisModel).filter_by(case_id=case_id).all():
            supp = json.loads(h.supporting_evidence) if h.supporting_evidence else []
            contra = json.loads(h.contradicting_evidence) if h.contradicting_evidence else []
            hypotheses.append({
                "id": f"H{len(hypotheses)+1}",
                "title": h.hypothesis,
                "score": h.confidence,
                "supporting_evidence": supp,
                "contradicting_evidence": contra
            })

        # Load Graph Entities & Relationships
        nodes = []
        for ge in session.query(GraphEntityModel).filter_by(case_id=case_id).all():
            props = json.loads(ge.properties) if ge.properties else {}
            nodes.append(props if props else {"id": ge.entity, "type": ge.entity_type})

        edges = []
        for gr in session.query(GraphRelationshipModel).filter_by(case_id=case_id).all():
            edges.append({
                "source": gr.source_entity,
                "relation": gr.relationship,
                "target": gr.target_entity,
                "confidence": gr.confidence
            })

        # Load Audit Trail / Steps
        audit_trail = []
        for step in session.query(InvestigationStepModel).filter_by(case_id=case_id).order_by(InvestigationStepModel.step_number).all():
            tool_args = {}
            if step.query:
                try:
                    tool_args = json.loads(step.query)
                except Exception:
                    tool_args = {"query": step.query}

            audit_trail.append({
                "step": step.step_number,
                "timestamp": step.timestamp,
                "selected_lead": f"Investigate {step.tool_name}",
                "llm_used": step.llm_used,
                "llm_provider": step.provider,
                "llm_model": step.model,
                "fallback_occurred": step.fallback_occurred,
                "tool_called": step.tool_name,
                "tool_args": tool_args,
                "rationale": step.rationale,
                "findings": step.result_summary,
                "stopping_decision": False
            })

        # Load Report
        report_record = session.query(ReportModel).filter_by(case_id=case_id).first()
        report = json.loads(report_record.report_data) if report_record and report_record.report_data else None

        return {
            "case_id": c_record.case_id,
            "status": c_record.status,
            "risk_score": c_record.risk_score,
            "risk_rating": c_record.risk_rating,
            "confidence_score": c_record.confidence_score,
            "summary": c_record.summary,
            "events": events,
            "iocs": iocs,
            "leads": leads,
            "hypotheses": hypotheses,
            "graph_summary": {"nodes": nodes, "edges": edges},
            "audit_trail": audit_trail,
            "report": report,
            "fallback_occurred": any(s["fallback_occurred"] for s in audit_trail) if audit_trail else False
        }
    except Exception as e:
        logger.error(f"Error loading case {case_id} from DB: {e}")
        return None
    finally:
        session.close()

def list_cases_from_db() -> List[Dict[str, Any]]:
    """
    Lists all saved cases in the database.
    """
    session: Session = SessionLocal()
    try:
        cases = session.query(CaseModel).order_by(CaseModel.id.desc()).all()
        return [
            {
                "case_id": c.case_id,
                "title": c.title,
                "status": c.status,
                "created_at": c.created_at,
                "updated_at": c.updated_at,
                "risk_score": c.risk_score,
                "risk_rating": c.risk_rating
            }
            for c in cases
        ]
    finally:
        session.close()

def delete_case_from_db(case_id: str) -> bool:
    """
    Deletes a case and all associated records by case_id.
    """
    session: Session = SessionLocal()
    try:
        c = session.query(CaseModel).filter_by(case_id=case_id).first()
        if c:
            session.delete(c)
            session.commit()
            return True
        return False
    except Exception as e:
        session.rollback()
        logger.error(f"Error deleting case {case_id}: {e}")
        return False
    finally:
        session.close()

def query_investigation_memory_db(case_id: str, query: str) -> List[Dict[str, Any]]:
    """
    Queries investigation steps for the active case matching a keyword query (Tool #11 implementation).
    """
    session: Session = SessionLocal()
    try:
        q_lower = query.lower()
        steps = session.query(InvestigationStepModel).filter_by(case_id=case_id).all()
        matched = []
        for s in steps:
            searchable = f"{s.tool_name} {s.query} {s.rationale} {s.result_summary}".lower()
            if q_lower in searchable or not query:
                matched.append({
                    "step_number": s.step_number,
                    "tool_name": s.tool_name,
                    "query": s.query,
                    "rationale": s.rationale,
                    "result_summary": s.result_summary,
                    "provider": s.provider,
                    "model": s.model,
                    "llm_used": s.llm_used,
                    "timestamp": s.timestamp
                })
        return matched
    finally:
        session.close()

def query_threat_intel_cache(case_id: str, indicator: str) -> Optional[Dict[str, Any]]:
    """
    Queries cached threat intelligence lookup for an indicator in the active case (Phase 3 Caching).
    """
    session: Session = SessionLocal()
    try:
        ind_clean = indicator.strip().lower()
        records = session.query(ThreatIntelResultModel).filter_by(case_id=case_id).all()
        for r in records:
            if r.indicator.strip().lower() == ind_clean and r.result:
                try:
                    data = json.loads(r.result)
                    data["status"] = "CACHED"
                    data["cached_from_timestamp"] = r.timestamp
                    return data
                except Exception:
                    pass
        return None
    finally:
        session.close()

def save_threat_intel_to_db(case_id: str, indicator: str, indicator_type: str, provider: str, result_dict: Dict[str, Any]) -> None:
    """
    Persists threat intelligence lookup result into ThreatIntelResultModel (Phase 3 Section 9).
    """
    session: Session = SessionLocal()
    try:
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        res_str = json.dumps(result_dict)

        existing = session.query(ThreatIntelResultModel).filter_by(case_id=case_id, indicator=indicator).first()
        if not existing:
            session.add(ThreatIntelResultModel(
                case_id=case_id,
                indicator=indicator,
                indicator_type=indicator_type,
                provider=provider,
                result=res_str,
                timestamp=now_str
            ))
        else:
            existing.provider = provider
            existing.result = res_str
            existing.timestamp = now_str
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Failed to persist ThreatIntelResult: {e}")
    finally:
        session.close()
