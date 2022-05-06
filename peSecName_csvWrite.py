import dateutil
import pandas
import pefile
import os
from matplotlib import pyplot
pyplot.rcParams["figure.figsize"] = (10, 6)

secNAme_mal = {}
secNAme_ben = {}
secName = []


# def get_peSection_name(path: str, secName: dict):
#     try:
#         pe = pefile.PE(path)
#     except pefile.PEFormatError:
#         return
#     else:
#         for section in pe.sections:
#             name = str(section.Name, 'utf-8').strip()
#             if name in secName:
#                 secName[name] += 1
#             else:
#                 secName[name] = 1
def get_peSection(path: str,type):
    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError:
        return
    else:
        cnt=0
        for section in pe.sections:
            cnt+=1
        with open("benmal_secVSfile.csv", 'a') as f:
            f.write(path.split('\\')[-1]+','+type+','+str(cnt)+','+str(os.stat(path).st_size)+'\n')
        

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
with open("benmal_secVSfile.csv", 'w') as f:
    f.write("name,type,sectionCount,fileSize\n")
for i in path_ben:
    get_peSection(i, "Benignware")
for i in path_mal:
    get_peSection(i, "Malware")

# ben = [[], []]
# for i in secNAme_ben.keys():
#     ben[0] += [i]
#     ben[1] += [secNAme_ben[i]]
# mal = [[], []]
# for i in secNAme_mal.keys():
#     mal[0] += [i]
#     mal[1] += [secNAme_mal[i]]
# print(ben)

    
