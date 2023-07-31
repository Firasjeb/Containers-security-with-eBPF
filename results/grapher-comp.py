import os
import sys
import re
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator
import pandas as pd
import numpy as np
import seaborn as sns

if len(sys.argv) != 2:
    print('Usage: {0} file'.format(sys.argv[0]))
    sys.exit(1)

file_name = sys.argv[1]

in_path = "datasource"
out_path = "plots"

file1 = os.path.join(in_path, file_name)
output_folder = os.path.join(out_path, "plot__" + file_name)
if not os.path.exists(output_folder):  
    os.makedirs(output_folder)

# Charger les données des deux fichiers CSV
res_no_ebpf = np.array([20,45, 93.4, 187.4,378])
res_ebpf = np.array([23,47, 104, 197.4,389.5])
size_transfert = np.array(["100 Mo","500 Mo", "1 Go", "2 Go","4 Go"])

df1 = {'size': size_transfert, 'value': res_no_ebpf, 'legend':'sans eBPF'}
df2 = {'size': size_transfert, 'value': res_ebpf, 'legend':'avec eBPF'}

# titre pour les graphiques
legend_1 = "avec eBPF"
legend_2 = "sans eBPF"

custom_palette = ['blue', 'red', 'green', 'orange', 'purple']


# Définition de la taille d'affichage globale
#sns.set(rc={'figure.figsize':40, 10), 'figure.dpi':100})
sns.set_style("whitegrid", {'grid.linestyle': '--'})

# Calcul des limites pour l'axe y
y_min = 0
y_max = max(res_ebpf.max(), res_no_ebpf.max())


# Graphique 1 - Comparaison des deux jeux de données
fig1, axes1 = plt.subplots(nrows=1, ncols=1, figsize=(35, 10))
sns.set(font_scale=1.5)
sns.lineplot(data=df1, x="size", y="value", label = df1['legend'], marker='<', markersize=10, )
sns.lineplot(data=df2, x="size", y="value", label = df2['legend'], marker='o', markersize=10)
#axes1.set(xlabel=, ylabel='Latence', )
axes1.set_ylim(y_min, y_max)  # Définir les limites de l'axe y
axes1.tick_params(axis='both', which='major', labelsize=18)
axes1.set_title("Evolution de la latence entre client et serveur en fonction de la taille des données", fontsize=18 )

plt.xlabel('Taille des données', fontsize=18)
plt.ylabel('Latence', fontsize=16)
plt.legend( loc='upper left')
fig1.savefig(output_folder + "/plot1.png", dpi=200)
plt.show()





