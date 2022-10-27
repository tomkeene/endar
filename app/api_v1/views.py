from flask import jsonify, request, current_app,abort
from . import api
from app import models, db
from sqlalchemy import func, or_
from flask_login import login_required,current_user
from app.utils.decorators import roles_required
from app.utils.jquery_filters import Filter
from datetime import datetime, timedelta
from itertools import groupby
import arrow
import json

@api.route('/health', methods=['GET'])
def get_health():
    return jsonify({"message":"ok"})

@api.route('/assets', methods=['GET','POST'])
@login_required
def assets():
    """
    return query results for dt table
    """
    payload = request.get_json()
    include_cols = request.args.get("columns", "no")

    session = current_app.db.session.query().order_by(models.Agent.last_active.desc())
    _filter = Filter(models, session,tables=["agents"])
    data = _filter.handle_request(
        payload,
        default_filter={"condition":"OR","rules":[{"field":"agents.id","operator":"is_not_null"}]},
        default_fields=["hostname", "edition", "local_addr", "cpu", "memory", "last_active_h", "agent_ref"]
    )
    if include_cols == "no":
        data.pop("columns", None)
    return jsonify(data)

@api.route('/groups', methods=['GET','POST'])
@login_required
def groups():
    """
    return query results for dt table
    """
    payload = request.get_json()
    include_cols = request.args.get("columns", "no")
    _filter = Filter(models, current_app.db.session.query(),tables=["groups"])
    data = _filter.handle_request(
        payload,
        default_filter={"condition":"OR","rules":[{"field":"groups.id","operator":"is_not_null"}]},
        default_fields=["id", "label", "precedence", "has_policy", "agent_count","group_ref"]
    )
    if include_cols == "no":
        data.pop("columns", None)
    return jsonify(data)

@api.route('/stats/agent-summary', methods=['GET'])
@login_required
def get_agent_stats():
    tenant_id = request.args.get("tenant-id", None)
    data = {
        "total_agents":models.Agent._query(as_count=True,tenant_id=tenant_id),
        "active_agents":models.Agent._query(last_active=24,as_count=True,tenant_id=tenant_id),
        "stale_agents":models.Agent._query(last_active=168,date_sort="lt",as_count=True,tenant_id=tenant_id),
        "os":{}
    }
    for record in models.Agent.query.with_entities(models.Agent.edition, func.count(models.Agent.edition)).group_by(models.Agent.edition).all():
        os = record[0] or "Unknown"
        data["os"][f"{os} OS"] = record[1]
    return jsonify(data)

@api.route('/graph/agent-registered', methods=['GET'])
@login_required
def graph_get_agent_registered():
    data = {}
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=60)
    delta = end_date - start_date

    agents = models.Agent.query.filter(models.Agent.date_added >= start_date).all()
    def grouper( item ):
        return item.date_added.day
    for ( (year), agents ) in groupby( agents, grouper ):
        agent_list = list(agents)
        label = agent_list[0].date_added.strftime("%Y-%m-%d")
        data[label] = len(agent_list)
    for i in range(delta.days + 1):
        day = (start_date + timedelta(days=i)).strftime("%Y-%m-%d")
        if day not in data:
            data[day] = 0
    return data

@api.route('/graph/agent-active', methods=['GET'])
@login_required
def graph_get_agent_active():
    data = {}
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=60)
    delta = end_date - start_date

    agents = models.Agent.query.filter(models.Agent.last_active >= start_date).filter(models.Agent.last_active != None).all()
    def grouper( item ):
        return item.last_active.day
    for ( (year), agents ) in groupby( agents, grouper ):
        agent_list = list(agents)
        label = agent_list[0].last_active.strftime("%Y-%m-%d")
        data[label] = len(agent_list)
    for i in range(delta.days + 1):
        day = (start_date + timedelta(days=i)).strftime("%Y-%m-%d")
        if day not in data:
            data[day] = 0
    return data

@api.route('/assets/<string:agent_key>', methods=['GET'])
@login_required
def get_asset(agent_key):
    data = Agent._query(key=agent_key,as_json=True)
    if not data:
        return jsonify({})
    return jsonify(data[0])

@api.route('/tables/<string:name>/rules', methods=['GET'])
@login_required
def get_table_rules(name):
    """
    return rules for the jquery table filters
    """
    tables = {
        "agent":models.Agent
    }
    table = tables.get(name)
    if not table:
        return jsonify({"message":"not found"}),404
    return jsonify(table.jquery_format())

@api.route('/policies/<int:id>/config', methods=['GET', 'POST'])
@login_required
def policy_config(id):
    policy = models.Policy.query.get(id)
    if not policy:
        return jsonify({"message": "not found"}), 404
    if request.method == "POST":
        if not current_user.has_role("admin"):
            abort(401)
        config = request.get_json()
        try:
            config = json.loads(config)
        except:
            return jsonify({"message": "invalid policy"}), 400
        policy.config = config
        db.session.commit()
    return jsonify(policy.config)

@api.route('/policies/<int:id>/compliance-tasks/<int:task_id>/enable', methods=['PUT'])
@roles_required("admin")
def add_compliance_task_to_policy(id, task_id):
    policy = models.Policy.query.get(id)
    if not policy:
        return jsonify({"message": "not found"}), 404
    task = models.ComplianceTask.query.get(task_id)
    if not task:
        return jsonify({"message": "not found"}), 404
    policy.compliance_tasks.append(task)
    db.session.commit()
    return jsonify({"message": "ok"})

@api.route('/policies/<int:id>/compliance-tasks/<int:task_id>/disable', methods=['PUT'])
@roles_required("admin")
def remove_compliance_task_to_policy(id, task_id):
    policy = models.Policy.query.get(id)
    if not policy:
        return jsonify({"message": "not found"}), 404
    task = models.ComplianceTask.query.get(task_id)
    if not task:
        return jsonify({"message": "not found"}), 404
    policy.compliance_tasks.remove(task)
    db.session.commit()
    return jsonify({"message": "ok"})

@api.route('/groups/<int:id>/agents/<int:agent_id>', methods=['PUT'])
@roles_required("admin")
def add_agent_to_group(id, agent_id):
    group = models.Group.query.get(id)
    if not group:
        return jsonify({"message": "not found"}), 404
    agent = models.Agent.query.get(agent_id)
    if not agent:
        return jsonify({"message": "not found"}), 404
    agent.groups.append(group)
    db.session.commit()
    return jsonify({"message": "ok"})

@api.route('/groups/<int:id>/agents/<int:agent_id>', methods=['DELETE'])
@roles_required("admin")
def remove_agent_from_group(id, agent_id):
    group = models.Group.query.get(id)
    if not group:
        return jsonify({"message": "not found"}), 404
    if group.default:
        return jsonify({"message": "agent can not be removed from default group"}), 400
    agent = models.Agent.query.get(agent_id)
    if not agent:
        return jsonify({"message": "not found"}), 404
    agent.groups.remove(group)
    db.session.commit()
    return jsonify({"message": "ok"})

@api.route('/tags/<int:id>', methods=['DELETE'])
@roles_required("admin")
def delete_tag(id):
    tag = models.Tag.query.get(id)
    if not tag:
        return jsonify({"message": "not found"}), 404
    db.session.delete(tag)
    db.session.commit()
    return jsonify({"message": "ok"})

@api.route('/tags/<int:id>/agents/<int:agent_id>', methods=['PUT'])
@roles_required("admin")
def add_agent_to_tag(id, agent_id):
    tag = models.Tag.query.get(id)
    if not tag:
        return jsonify({"message": "not found"}), 404
    agent = models.Agent.query.get(agent_id)
    if not agent:
        return jsonify({"message": "not found"}), 404
    agent.tags.append(tag)
    db.session.commit()
    return jsonify({"message": "ok"})

@api.route('/tags/<int:id>/agents/<int:agent_id>', methods=['DELETE'])
@roles_required("admin")
def remove_agent_from_tag(id, agent_id):
    tag = models.Tag.query.get(id)
    if not tag:
        return jsonify({"message": "not found"}), 404
    agent = models.Agent.query.get(agent_id)
    if not agent:
        return jsonify({"message": "not found"}), 404
    agent.tags.remove(tag)
    db.session.commit()
    return jsonify({"message": "ok"})

@api.route('/compliance-tasks/<int:id>/results', methods=['GET'])
@login_required
def compliance_results_for_agent(id):
    data = []
    agent_id = request.args.get("agent_id")
    _query = models.ComplianceTaskResults.query.filter(models.ComplianceTaskResults.task_id == id)
    if agent_id:
        _query = _query.filter(models.ComplianceTaskResults.agent_id == agent_id)
    for record in _query.all():
        data.append(record.as_dict())
    return data

@api.route('/compliance-tasks/<int:id>/validate/status', methods=['PUT'])
@roles_required("admin")
def update_validate_status(id):
    data = request.get_json()
    task = models.ComplianceTask.query.get(id)
    if not task:
        return jsonify({"message":"not found"}),404
    task.validation_enabled = data["status"]
    return jsonify({"message":"ok"})

@api.route('/compliance-tasks/<int:id>/enforce/status', methods=['PUT'])
@roles_required("admin")
def update_enforce_status(id):
    data = request.get_json()
    task = models.ComplianceTask.query.get(id)
    if not task:
        return jsonify({"message":"not found"}),404
    task.enforcement_enabled = data["status"]
    return jsonify({"message":"ok"})

@api.route('/compliance-tasks/<int:id>/config', methods=['POST'])
@roles_required("admin")
def update_compliance_task_config(id):
    task = models.ComplianceTask.query.get(id)
    if not task:
        return jsonify({"message":"not found"}),404
    data = request.get_json()
    task.set_tags_by_name(data["tags"])
    # validation
    cmd = data["validate"]["cmd"]
    if not cmd:
        return jsonify({"message": "missing validate command"}), 400
    if "{file}" in cmd:
        url = data["validate"]["url"]
        if not url:
            return jsonify({"message": "missing validate url"}), 400
        extension = data["validate"]["ext"]
        if not extension:
            return jsonify({"message": "missing validate extension"}), 400
        extension = extension.replace(".","")
        version = task.validate.get("version", 1) + 1
        file_name = f"v{version}_{task.name}.{extension}"
        interpreter, args = cmd.split("{file}")
        validate_record = {
            "exec": False,
            "url": url,
            "interpreter": interpreter,
            "args": args,
            "version": version,
            "file": file_name,
            "cmd": cmd
        }
    else:
        validate_record = {
            "exec": True,
            "cmd": cmd
        }

    # enforcement
    cmd = data["enforce"]["cmd"]
    if "{file}" in cmd:
        url = data["enforce"]["url"]
        if not url:
            return jsonify({"message": "missing enforce url"}), 400
        extension = data["enforce"]["ext"]
        if not extension:
            return jsonify({"message": "missing enforce extension"}), 400
        version = task.enforce.get("version", 1) + 1
        file_name = f"e{version}_{task.name}.{extension}"
        interpreter, args = cmd.split("{file}")
        enforce_record = {
            "exec": False,
            "url": url,
            "interpreter": interpreter,
            "args": args,
            "version": version,
            "file": file_name,
            "cmd": cmd
        }
    else:
        if not cmd:
            enforce_record = {}
        else:
            enforce_record = {
                "exec": True,
                "cmd": cmd
            }

    task.validate = validate_record
    task.enforce = enforce_record
    task.label = data["label"] or "default"
    task.timeout = data["timeout"] or 10
    task.interval = data["interval"] or 300
    db.session.commit()
    return jsonify({"message":"ok"})

#------------ GRAPH ------------
@api.route('/graph/stats/os', methods=['GET'])
@login_required
def graph_get_os_count():
    data = {
        "labels":[],
        "series":[]
    }
    for record in models.Agent.query.with_entities(models.Agent.edition, func.count(models.Agent.edition)).group_by(models.Agent.edition).all():
        data["labels"].append(record[0] or "unknown")
        data["series"].append(record[1])
    return jsonify(data)

@api.route('/graph/stats/performance', methods=['GET'])
@login_required
def graph_get_performance_stats():
    agent_id = request.args.get("agent-id", None)
    span = request.args.get("span", "5")

    dt = datetime.utcnow() - timedelta(minutes=int(span))
    _query = models.Performance.query.with_entities(
        func.max(models.Performance.mem_total).label("mem_total"),
        func.max(models.Performance.swap_total).label("swap_total"),
        func.avg(models.Performance.cpu_load).label("cpu_load"),
        func.avg(models.Performance.mem_used).label("mem_used"),
        func.avg(models.Performance.mem_free).label("mem_free"),
        func.avg(models.Performance.mem_percent_used).label("mem_percent_used"),
        func.avg(models.Performance.swap_used).label("swap_used"),
        func.avg(models.Performance.swap_free).label("swap_free"),
        func.avg(models.Performance.swap_percent_used).label("swap_percent_used"),
        func.avg(models.Performance.swapped_in).label("swapped_in"),
        func.avg(models.Performance.swapped_out).label("swapped_out")
    ).filter(or_(models.Performance.date_added > dt, models.Performance.date_updated > dt))
    if agent_id:
        _query = _query.filter(models.Performance.agent_id == agent_id)
    metric = _query.first()

    data = {
      "mem-total":metric.mem_total,
      "swap-total":metric.swap_total,
      "cpu-load":metric.cpu_load,
      "mem-used":metric.mem_used,
      "mem-free":metric.mem_free,
      "mem-percent-used": metric.mem_percent_used,
      "swap-used":metric.swap_used,
      "swap-free":metric.swap_free,
      "swap-percent-used":metric.swap_percent_used,
      "swapped-in":metric.swapped_in,
      "swapped-out":metric.swapped_out
    }
    return jsonify(data)

@api.route('/graph/stats/memory-used', methods=['GET'])
@login_required
def graph_get_memory_used():
    data = []
    agent_id = request.args.get("agent-id", None)
    span = request.args.get("span", "5")

    dt = datetime.utcnow() - timedelta(minutes=int(span))
    _query = models.Performance.query.filter(or_(models.Performance.date_added > dt, models.Performance.date_updated > dt))
    if agent_id:
        _query = _query.filter(models.Performance.agent_id == agent_id)
    chart_line = {
        "name": "Memory Used",
        "data": []
    }
    for record in _query.all():
        chart_line["data"].append({"x":str(record.date_added),"y":round(record.mem_percent_used,1)})
    data.append(chart_line)
    return jsonify({"series":data})

@api.route('/graph/stats/cpu-load', methods=['GET'])
@login_required
def graph_get_cpu_load():
    data = []
    agent_id = request.args.get("agent-id", None)
    span = request.args.get("span", "15")

    dt = datetime.utcnow() - timedelta(minutes=int(span))
    _query = models.Performance.query.filter(or_(models.Performance.date_added > dt, models.Performance.date_updated > dt))
    if agent_id:
        _query = _query.filter(models.Performance.agent_id == agent_id)
    chart_line = {
        "name": "CPU Load",
        "data": []
    }
    for record in _query.all():
        cpu_load = record.cpu_load or 0
        chart_line["data"].append({"x":str(record.date_added),"y":round(cpu_load,1)})
    data.append(chart_line)
    return jsonify({"series":data})
