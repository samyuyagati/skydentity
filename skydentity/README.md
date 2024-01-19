# Build
To build as an [editable] module from source, run the following line from the top-level skydentity directory:
```
pip install [--editable] .
```

# Uploading client policy to Firestore
Upload the policy to the Firestore Account using the script `skydentity/scripts/upload_policy.py`. Specify the arguments --policy to the path to the policy to be uploaded, --cloud gcp, --public-key as the string of the public key of the broker, and --credentials as the path to the credentials for Firestore; this should be the json keyfile from setting up a service account on GCP, and the service account should have the role roles/datastore.user.

Example usage:
```
python scripts/upload_policy.py --policy policies/config/skypilot_eval.yaml --public-key skypilot_eval --credentials <path-to-service-account-json-key-file> --cloud gcp
``` 

# To run unit tests, run the following command from the `tests` directory
```
python3 -m unittest discover
```
