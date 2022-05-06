import dateutil
import pandas
import pefile
from matplotlib import pyplot
pyplot.rcParams["figure.figsize"] = (10, 6)

secNAme_mal = {}
secNAme_ben = {}
secName = []


def get_peSection_name(path: str, secName: dict):

    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError:
        return
    else:
        for section in pe.sections:
            name=str(section.Name,'utf-8').strip()
            if name in secName:
                secName[name] += 1
            else:
                secName[name] = 1


path_ben = [
    "Mini Data\Samples\BenignSample1.exe",
    "Mini Data\Samples\BenignSample2.exe",
    "Mini Data\Samples\BenignSample3.exe",
    "Mini Data\Samples\BenignSample4.exe"
]
path_mal = [
    "Mini Data\Samples\MalSample1.exe", "Mini Data\Samples\MalSample2.exe",
    "Mini Data\Samples\MalSample3.exe", "Mini Data\Samples\MalSample4.exe"
]

for i in path_ben:
    get_peSection_name(i, secNAme_ben)
for i in path_mal:
    get_peSection_name(i, secNAme_mal)

# malware = pandas.read_csv("malware_data.csv")
# malware['fs_date'] = [dateutil.parser.parse(d) for d in malware['fs_bucket']]

# for i in secNAme_ben.keys():
#     if i not in secNAme_mal.keys():
#         secNAme_mal[i]=0
# for i in secNAme_mal.keys():
#     if i not in secNAme_ben.keys():
#         secNAme_ben[i]=0
ben = [[],[]]
for i in secNAme_ben.keys():
    ben[0]+=[i]
    ben[1]+=[secNAme_ben[i]]
mal = [[],[]]
for i in secNAme_mal.keys():
    mal[0]+=[i]
    mal[1]+=[secNAme_mal[i]]
# print(ben)
with open("benmal_data.csv",'w') as f:
    f.write("name,type\n")
    for i in secNAme_ben:
        for c in range(secNAme_ben[i]):
            f.write(str(i)+",ben"+'\n')
    for i in secNAme_mal:
        for c in range(secNAme_mal[i]):
            f.write(str(i)+",mal"+'\n')
        
pyplot.plot(ben[0], ben[1], 'ro', label="Benignware", markersize=3)
pyplot.plot(mal[0], mal[1], 'bo', label="Malware", markersize=3)
pyplot.legend(framealpha=1, markerscale=3.0)
pyplot.xlabel("Name")
pyplot.ylabel("Number of detections")
pyplot.ylim([-1, 5])
pyplot.title("")
# pyplot.show()
# pyplot.gcf().clf()
pyplot.savefig("Figure_9-5.png")