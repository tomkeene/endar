from flask import jsonify, request, current_app,abort
from . import api
from app.models import *
from flask_login import login_required,current_user
from app.utils.decorators import roles_required, has_valid_tenant_key, has_valid_tenant_and_agent
import arrow
import json
import zlib

@api.route('/register', methods=['POST'])
@has_valid_tenant_key
def register_agent(tenant):
    if agent_key := request.headers.get("aid"):
        if agent := Agent.find(agent_key):
            return jsonify({"registered":True,"msg":"agent is already registered","agent_id":agent.key})

    payload = request.get_json()
    agent_id = tenant.register_agent(payload)
    return jsonify({"registered":True,"msg":"agent successfully registered","agent_id":agent_id})

@api.route("/policy",methods=["GET","POST"])
@has_valid_tenant_and_agent
def get_policy(agent):
    data = request.get_json()
    if data:
        for key, value in data.items():
            setattr(agent, key, value)
    agent.last_active = arrow.utcnow().datetime
    db.session.commit()
    return jsonify(agent.policy_format())

@api.route("/compliance",methods=["POST"])
@has_valid_tenant_and_agent
def post_compliance(agent):
    data = request.get_json()
    task = ComplianceTask.query.filter(ComplianceTask.name == data["name"]).first()
    record = {
        "validate": data["validate"]["output"],
        "validate_rtn_code": int(data["validate"]["rtn_code"]),
        "agent_id": agent.id,
        "tenant_id": agent.tenant_id
    }
    if data.get("enforce"):
        record["enforce"] = data["enforce"]["output"]
        record["enforce_rtn_code"] = int(data["enforce"]["rtn_code"])
    result = ComplianceTaskResults(**record)
    task.results.append(result)
    db.session.commit()
    return jsonify({"message":"ok"})

#TODO - offload collection to a separate service
@api.route("/collection",methods=["POST"])
@has_valid_tenant_and_agent
def data_collection(agent):
    data = zlib.decompress(request.data).decode("utf-8")
    record = json.loads(data)
    data = record["data"]
    if record["name"] == "get-performance":
        data["agent_id"] = agent.id
        data["tenant_id"] = agent.tenant_id
        p = Performance(**data)
        db.session.add(p)
    elif record["name"] == "get-disk":
        AgentDisk.query.filter(AgentDisk.agent_id == agent.id).delete()
        db.session.commit()
        for part in data:
            part.pop("date_collected",None)
            part["agent_id"] = agent.id
            part["tenant_id"] = agent.tenant_id
            d = AgentDisk(**part)
            db.session.add(d)
    db.session.commit()
    return jsonify({"message":"ok"})
