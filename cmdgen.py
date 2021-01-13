import numpy as np
uuids = ["00000001", "00000002", "00000003"]
seen = {}
cmd_file = ""
for i in range(30):
    if i > 0:
        cmd_file += "\n"
    uuid = np.random.choice(uuids)
    test_res = np.random.randint(3)
    if test_res == 2:
        if uuid in seen:
            cmd_file += uuid
        else:
            cmd_file += uuid + " " + str(np.random.randint(2))
    else:
        cmd_file += uuid + " " + str(test_res)
    seen[uuid] = 1
print(cmd_file)