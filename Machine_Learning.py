import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.metrics import roc_curve, auc
from sklearn.model_selection import learning_curve
from sklearn.model_selection import train_test_split

# Reading in csv file
df = pd.read_csv('Training.csv')

# check if the preprocessed data without the columns below is about 92-93% accuracy
# which is about 4% lower with this data
# data = df.drop(
#    ['Result', 'URL_of_Anchor', 'SFH', 'Abnormal_URL', 'on_mouseover', "age_of_domain", "DNSRecord", "web_traffic",
#     "Page_Rank", "Google_Index", "Links_pointing_to_page", "Statistical_report"], axis=1)

# remove the result columns is about 96-97%
label = df['Result']
data2 = df.drop(['Result'], axis=1)

# split a dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(data2, label, test_size=0.2, random_state=42)
clf = RandomForestClassifier().fit(X_train, y_train)
y_pred = clf.predict(X_test)

accuracy = clf.score(X_test, y_test)
print(f"Accuracy: {accuracy}")

'''
[TN FP]
[FN TP]
'''

print("\nConfusion Matrix: ")
cm = confusion_matrix(y_test, y_pred)

plt.figure()  # Create a new figure
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
plt.xlabel('Predicted label')
plt.ylabel('True label')
plt.title('Confusion Matrix')
plt.savefig('cm.png')
print("Plotted Confusion Matrix check cm.png")

# Calculate ROC curve and AUC
fpr, tpr, _ = roc_curve(y_test, y_pred)
roc_auc = auc(fpr, tpr)

# Plot ROC curve
plt.figure()
plt.plot(fpr, tpr, color='blue', lw=2, label='ROC curve (AUC = %0.2f)' % roc_auc)
plt.plot([0, 1], [0, 1], color='gray', linestyle='--')  # Random classifier line
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('ROC Curve')
plt.legend(loc='lower right')
plt.savefig('roc.png')
print("Plotted ROC curve check roc.png")

# Plot feature importances
feature_importances = clf.feature_importances_
fi = plt
fi.figure()
fi.bar(data2.columns, feature_importances)
fi.xticks(rotation=90)
fi.xlabel('Features')
fi.ylabel('Importance')
fi.title('Feature Importance')
fi.tight_layout()
fi.savefig('fi.png')
print("Plotted Feature Importance check fi.png")

# Plot learning curve
train_sizes, train_scores, test_scores = learning_curve(clf, data2, label, cv=5)
lc = plt
lc.figure()
lc.plot(train_sizes, np.mean(train_scores, axis=1), label='Training score')
lc.plot(train_sizes, np.mean(test_scores, axis=1), label='Cross-validation score')
lc.xlabel('Number of Training Examples')
lc.ylabel('Accuracy Score')
lc.title('Learning Curve')
lc.legend()
lc.savefig('lc.png')
print("Plotted Learning Curve check lc.png")
