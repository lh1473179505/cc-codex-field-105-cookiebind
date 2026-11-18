def migrate(groups, name, cgroup):
    groups.items[name]["cgroup"] = cgroup

def revoke(groups):
    groups.epoch += 1
