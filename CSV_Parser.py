import csv
filename = "DATA and DOCS\Apps to IP.csv"
fields = []
rows = []
with open(filename, 'r') as csvfile:
    csvreader = csv.reader(csvfile)
 
    fields = next(csvreader)
 
    for row in csvreader:
        rows.append(row)
 
print('Field names are:' + ', '.join(field for field in fields))
 
print('\nFirst 5 rows are:\n')
for row in rows[:]:
    for col in row:
        print("%10s" % col, end=" "),
    print('\n')