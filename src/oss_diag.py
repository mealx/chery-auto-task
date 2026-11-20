#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OSS 直传自检：把服务端下发的 policy 摊开看，再按条件反推上传表单。

用法（本地或 Actions 里都能跑）:
  CHERY_TOKEN=xxx python src/oss_diag.py          # 只诊断：打印 policy 条件 + 将要发的 key
  CHERY_TOKEN=xxx python src/oss_diag.py --test   # 再传 64KB 假数据，让 OSS 直接说出哪条不满足

输出重点:
  - sts 返回了哪些字段（bucket / endpoint / dir / securityToken ...）
  - policy.conditions 原文：key 前缀、content-length-range、Content-Type 都在这里
  - 按 conditions 推导出来的 key / Content-Type / 大小上限
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import daily  # noqa: E402


def main():
    token = daily.get_access_token()
    sts = daily.enc_get("/web/community/common/sts/signature", token)["data"]
    pol, plan = daily.policy_plan(sts["policy"])

    print("sts keys      :", sorted(sts.keys()))
    print("bucket        :", sts.get("bucket"))
    print("endpoint      :", sts.get("endpoint"))
    print("dir           :", sts.get("dir"))
    print("expiration    :", pol.get("expiration"))
    print("conditions    :")
    for c in pol.get("conditions") or []:
        print("   ", json.dumps(c, ensure_ascii=False))
    print("-> key_prefix  :", plan["key_prefix"] or plan["key_eq"])
    print("-> content_type:", plan["content_type"])
    print("-> size range  :", plan["min_len"], "..", plan["max_len"])
    print("-> 将上传为    :", daily._upload_key(plan, sts, 0, "mp4"))

    if "--test" in sys.argv:
        print("\n--- 试传 64KB 假数据（只为看 OSS 真实回包）---")
        try:
            print("试传成功:", daily.oss_upload(token, b"\x00" * 65536, tries=1))
        except Exception as e:
            print("试传失败:", e)


if __name__ == "__main__":
    main()
