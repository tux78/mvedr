#!/usr/bin/env python3
# v0.1
# Script to collect MVISION EDR Threats

import requests
import time
import json
import sys
import os
import pytz

from datetime import datetime, timedelta
from dateutil import tz

class EDR():
  def __init__(self):
    self.iam_url = "iam.mcafee-cloud.com/iam/v1.1"
    self.base_url = "soc.eu-central-1.trellix.com"
    self.edr_client_id = edr_client_id
    self.edr_client_secret = edr_client_secret
    self.initial_pull = 10
    self.limit = 1000

    self.session = requests.Session()

    creds = (self.edr_client_id, self.edr_client_secret)

    self.bookmark = '{0}/bookmark'.format(log_dir)
    if os.path.isfile(self.bookmark):
      bookmark_file = open(self.bookmark, 'r')
      last_detection = datetime.strptime(bookmark_file.read(), '%Y-%m-%dT%H:%M:%SZ')
      last_detection_utc = last_detection.replace(tzinfo=pytz.UTC)
      next_pull = last_detection_utc.astimezone(tz.tzlocal()) + timedelta(seconds=1)
      bookmark_file.close()
    else:
      next_pull = datetime.now() - timedelta(days=self.initial_pull)
    self.epoch_pull = str(datetime.timestamp(next_pull)*1000)[:13]

    self.auth(creds)

  def auth(self, creds):
    try:
      payload = {
        'scope': 'soc.hts.c soc.hts.r soc.rts.c soc.rts.r soc.qry.pr',
        'grant_type': 'client_credentials',
        'audience': 'mcafee'
      }

      headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
      }

      res = self.session.post('https://{0}/token'.format(self.iam_url), headers=headers, data=payload, auth=creds)
      if res.ok:
        token = res.json()['access_token']
        self.session.headers = {'Authorization': 'Bearer {}'.format(token)}
    except Exception as error:
      raise

  def get_threats(self):
    try:
      tnextFlag = True
      skip = 0
      filter = {}
      severities = ["s0", "s1", "s2", "s3", "s4", "s5"]
      filter['severities'] = severities
      filter['score_Range'] = [30]

      while (tnextFlag):
        res = self.session.get(
          'https://api.{0}/ft/api/v2/ft/threats?sort=-lastDetected&filter={1}&from={2}&limit={3}&skip={4}' \
            .format(self.base_url, json.dumps(filter), self.epoch_pull, self.limit, skip))

        if res.ok:
          res = res.json()
          if int(res['skipped']) + int(res['items']) == int(res['total']):
            tnextFlag = False
          else:
            skip = int(res['skipped']) + int(res['items'])

          if len(res['threats']) > 0:
            if os.path.isfile(self.bookmark):
              bookmark_file = open(self.bookmark, 'r')
              last_detection = datetime.strptime(bookmark_file.read(), '%Y-%m-%dT%H:%M:%SZ')
              bookmark_file.close()
              if (datetime.strptime(res['threats'][0]['lastDetected'], '%Y-%m-%dT%H:%M:%SZ')) > last_detection:
                bookmark_file = open(self.bookmark, 'w')
                bookmark_file.write(res['threats'][0]['lastDetected'])
                bookmark_file.close()
            else:
              bookmark_file = open(self.bookmark, 'w')
              bookmark_file.write(res['threats'][0]['lastDetected'])
              bookmark_file.close()

            for threat in res['threats']:
              affhosts = self.get_affected_hosts(threat['id'])
              for host in affhosts:
                detections = self.get_detections(threat['id'], host['id'])
                for detection in detections:
                  threat['detection'] = detection
                  traceid = detection['traceId']
                  maguid = detection['host']['maGuid']
                  sha256 = detection['sha256']
                  threat['url'] = 'https://ui.{0}/monitoring/#/workspace/72,TOTAL_THREATS,{1}?traceId={2}&maGuid={3}&sha256={4}' \
                    .format(self.base_url, threat['id'], traceid, maguid, sha256)

                  self.output_threat(threat)

    except Exception as error:
      raise

  def get_affected_hosts(self, threatId):
    try:
      skip = 0
      anextFlag = True
      affhosts = []

      while (anextFlag):

        res = self.session.get(
          'https://api.{0}/ft/api/v2/ft/threats/{1}/affectedhosts?sort=-rank&from={2}&limit={3}&skip={4}' \
            .format(self.base_url, threatId, self.epoch_pull, self.limit, skip))

        if res.ok:
          res = res.json()
          if int(res['skipped']) + int(res['items']) == int(res['total']):
            anextFlag = False
          else:
            skip = int(res['skipped']) + int(res['items'])

          if len(affhosts) == 0:
            affhosts = res['affectedHosts']
          else:
            for affhost in res['affectedHosts']:
              affhosts.append(affhost)

      return affhosts

    except Exception as error:
      raise

  def get_detections(self, threatId, affhost):
    try:
      skip = 0
      dnextFlag = True
      detections = []

      while (dnextFlag):

        filter = {
          'affectedHostId': affhost
        }

        res = self.session.get(
          'https://api.{0}/ft/api/v2/ft/threats/{1}/detections?sort=-rank&from={2}&filter={3}&limit={4}&skip={5}' \
            .format(self.base_url, threatId, self.epoch_pull, json.dumps(filter), self.limit, skip))

        if res.ok:
          res = res.json()
          if int(res['skipped']) + int(res['items']) == int(res['total']):
            dnextFlag = False
          else:
            skip = int(res['skipped']) + int(res['items'])

          if len(detections) == 0:
            detections = res['detections']
          else:
            for detection in res['detections']:
              detections.append(detection)

      return detections

    except Exception as error:
      raise

  def output_threat(self, threat):
    if os.path.exists(threat_dir) is False:
      os.mkdir(threat_dir)
    ptime_detect = datetime.now()
    filename = 'EDR_{}.log'.format(ptime_detect.strftime('%Y%m%d%H'))
    file = open('{}/{}'.format(threat_dir, filename), 'a')
    file.write(json.dumps(threat))
    file.write("\r\n")
    file.close()

if __name__ == '__main__':

  edr_client_id = "<EDR_CLIENT_ID>"
  edr_client_secret = "<EDR_CLIENT_SECRET>"

  log_dir = './logs'
  threat_dir = './threats'

  while True:
    try:
      edr = EDR()
      edr.get_threats()
      edr.session.close()
      time.sleep(300)
    except Exception as error:
      time.sleep(60)
