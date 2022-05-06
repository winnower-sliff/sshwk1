import dateutil
import pandas
import pefile
from matplotlib import pyplot
import seaborn as sns
pyplot.rcParams["figure.figsize"] = (10, 6)

datas=pandas.read_csv("benmal_secVSfile.csv")
# datas=datas[datas.type.isin(['ben','mal'])]
# datas["times"]=pandas.to_numeric(datas["times"])
print(datas)
sns.relplot(x='sectionCount',y='fileSize',hue='type',data=datas)
pyplot.legend(framealpha=1, markerscale=3.0)
# pyplot.xlabel("Name")
# pyplot.ylabel("Number of detections")
# pyplot.ylim([-1, 5])
pyplot.show()
# pyplot.savefig('peSecFile.png')
# malware = pandas.read_csv("malware_data.csv")
# malware = malware[malware.positives>45][malware.type.isin(['worm','trojan'])]
# seaborn.countplot(x='positives', hue='type', data=malware)
# pyplot.show(