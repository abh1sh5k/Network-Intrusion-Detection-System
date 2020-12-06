import pandas as pd 
import numpy as np
import pickle			

#selecting columns which are present in the training data
order=['src_bytes', 'count', 'service', 'srv_count', 'protocol_type',
       'diff_srv_rate', 'same_srv_rate', 'flag', 'dst_bytes',
       'srv_serror_rate', 'logged_in', 'duration', 'lnum_compromised',
       'wrong_fragment', 'is_guest_login', 'num_failed_logins']

#reading records file
df=pd.read_csv('records.csv')

#slicing columns which are present in training set
df=df[(df.columns)&(order)]

#setting the order
df[order]


##converting object to int8
df['protocol_type'] = df['protocol_type'].astype('category')
df['service'] = df['service'].astype('category')
df['flag'] = df['flag'].astype('category')
cat_columns = df.select_dtypes(['category']).columns
df[cat_columns] = df[cat_columns].apply(lambda x: x.cat.codes)

##feeding data to intrusion detection model
import pickle
loaded_model = pickle.load(open('finalized_model.sav','rb'))

data=df.to_numpy()


result = loaded_model.predict(data)

print(result)

l=['Normal','DoS','Probe','R2L','U2R']
l=np.array(l)
for x in result:
    for y in range(len(x)):
        if x.sum()==0:
            print("Normal")
            break
        if x[y]==1:
            print(l[y])
            break
