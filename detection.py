
import pandas as pd
import urllib
import csv
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier


from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report
import pickle
import warnings
import pickle
warnings.filterwarnings("ignore")

# Load the csv file
df = pd.read_csv("main_data.csv")

print(df.head())

# Select independent and dependent variable
X = df[["Duration", "src_bytes", "dst_bytes", "logged_in","Count"]]
Y = df["Class"]

# y=list(set(Y.values))
# print(y)

# Split the dataset into train and test
X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.3, random_state=50)

# Feature scaling
sc = StandardScaler()
X_train = sc.fit_transform(X_train)
X_test= sc.transform(X_test)

# Instantiate the model
classifier = DecisionTreeClassifier()

# Fit the model
classifier.fit(X_train, y_train)
print("Classification score: ",classifier.score(X_train, y_train))

# Make pickle file of our model
pickle.dump(classifier, open("model.pkl", "wb"))