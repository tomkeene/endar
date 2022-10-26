from flask import render_template, redirect, url_for, abort, flash, request, \
    current_app, jsonify
from . import main
from app.models import *
from flask_login import login_required,current_user
from app.utils.decorators import roles_required,roles_accepted
import arrow
import uuid

@main.route('/', methods=['GET'])
@login_required
def home():
    tenant = Tenant.query.first()
    return render_template("home.html",tenant=tenant)

@main.route('/agents', methods=['GET'])
@login_required
def agents():
    tenant = Tenant.query.first()
    filters = Agent.jquery_format()
    return render_template("assets.html",tenant=tenant,jquery_filters=filters)

@main.route('/agents/<string:id>', methods=['GET', 'POST'])
@main.route('/agents/<string:id>/summary', methods=['GET', 'POST'])
@login_required
def view_agent(id):
    agent = Agent.query.filter(Agent.key == id).first()
    if not agent:
        abort(404)
    groups = Group.query.all()
    tags = Tag.query.all()
    return render_template("view_agent.html", agent=agent,
        groups=groups, tags=tags, tab_active="summary")

@main.route('/agents/<string:id>/performance', methods=['GET', 'POST'])
@login_required
def view_agent_performance(id):
    agent = Agent.query.filter(Agent.key == id).first()
    if not agent:
        abort(404)
    disks = AgentDisk.query.filter(AgentDisk.agent_id == agent.id).all()
    return render_template("view_agent_performance.html", agent=agent,
        tab_active="performance", disks=disks)

@main.route('/agents/<string:id>/compliance', methods=['GET', 'POST'])
@login_required
def view_agent_compliance(id):
    agent = Agent.query.filter(Agent.key == id).first()
    if not agent:
        abort(404)
    return render_template("view_agent_compliance.html", agent=agent,
        tab_active="compliance")

@main.route('/agents/<string:id>/compliance/results/<int:task_id>', methods=['GET', 'POST'])
@login_required
def view_agent_compliance_results_for_task(id, task_id):
    agent = Agent.query.filter(Agent.key == id).first()
    if not agent:
        abort(404)
    task = ComplianceTask.query.get(task_id)
    if not task:
        abort(404)
    results = agent.compliance_results.filter(ComplianceTaskResults.task_id == task_id).order_by(ComplianceTaskResults.id.desc()).all()
    return render_template("view_agent_compliance_results.html", agent=agent,
        task=task, results=results)

@main.route('/groups', methods=['GET','POST'])
@login_required
def groups():
    if request.method == "POST":
        if not current_user.has_role("admin"):
            abort(401)
        label = request.form["label"]
        group = Group.add(current_user.tenant_id, label)
        flash("Created new group", "success")
        return redirect(url_for("main.view_group",id=group.id))
    groups = Group.query.all()
    return render_template("groups.html", groups=groups)

@main.route('/groups/<int:id>', methods=['GET', 'POST'])
@login_required
def view_group(id):
    group = Group.query.get(id)
    if not group:
        abort(404)
    if request.method == "POST":
        if not current_user.has_role("admin"):
            abort(401)
        group.label = request.form["label"]
        group.precedence = request.form["precedence"]
        if request.form["policy"] != "0":
            group.policy_id = request.form["policy"]
        db.session.commit()
        flash("Updated group", "success")
    policies = Policy.query.all()
    agents = Agent.query.all()
    group_agents = group.agents.all()
    return render_template("view_group.html",
        agents=agents, group_agents=group_agents,
        group=group, policies=policies)

@main.route('/tags', methods=['GET','POST'])
@login_required
def tags():
    if request.method == "POST":
        if not current_user.has_role("admin"):
            abort(401)
        name = request.form["name"]
        Tag.add(current_user.tenant_id, name)
        flash("Created new tag", "success")
        return redirect(url_for("main.tags"))
    tags = Tag.query.all()
    return render_template("tags.html", tags=tags)

@main.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    tenant = Tenant.query.first()
    if request.method == "POST":
        if not current_user.has_role("admin"):
            abort(401)
        tenant.name = request.form.get("name")
        tenant.contact_email = request.form.get("email")
        db.session.commit()
        flash("Edited tenant settings","success")
        return redirect(url_for("main.settings"))
    return render_template("management/settings.html", tenant=tenant)

@main.route('/policies', methods=['GET','POST'])
@login_required
def policies():
    if request.method == "POST":
        if not current_user.has_role("admin"):
            abort(401)
        label = request.form["label"]
        policy = Policy.add(current_user.tenant_id, label)
        flash("Created new policy", "success")
        return redirect(url_for("main.view_policy",id=policy.id))
    policies = Policy.query.all()
    return render_template("policies.html",
        policies=policies)

@main.route('/policies/<int:id>', methods=['GET', 'POST'])
@login_required
def view_policy(id):
    policy = Policy.query.get(id)
    if not policy:
        abort(404)
    if request.method == "POST":
        if not current_user.has_role("admin"):
            abort(401)
        policy.label = request.form["label"]
        policy.headers = request.form["headers"]
        policy.url = request.form["url"]
        db.session.commit()
        flash("Updated policy", "info")
    compliance_tasks = ComplianceTask.query.all()
    policy_compliance_tasks = policy.compliance_tasks.all()
    return render_template("view_policy.html",
    compliance_tasks=compliance_tasks,
    policy_compliance_tasks=policy_compliance_tasks, policy=policy)

@main.route('/compliance-tasks', methods=['GET', 'POST'])
@login_required
def compliance_tasks():
    if request.method == "POST":
        if not current_user.has_role("admin"):
            abort(401)
        label = request.form["label"]
        task = ComplianceTask.add(current_user.tenant_id, label)
        flash("Created new task", "success")
        return redirect(url_for("main.view_compliance_task",id=task.id))
    tasks = ComplianceTask.query.all()
    return render_template("compliance_tasks.html", tasks=tasks)

@main.route('/compliance-task/<int:id>', methods=['GET', 'POST'])
@login_required
def view_compliance_task(id):
    task = ComplianceTask.query.get(id)
    if not task:
        abort(404)
    tags = task.get_tags_for_form()
    return render_template("view_compliance_task.html", task=task, tags=tags)

@main.route('/compliance-task/<int:id>/results', methods=['GET', 'POST'])
@login_required
def view_compliance_task_results(id):
    task = ComplianceTask.query.get(id)
    if not task:
        abort(404)
    results = task.results.order_by(ComplianceTaskResults.id.desc()).all()
    return render_template("view_compliance_task_results.html", task=task,
        results=results)
