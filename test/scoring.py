from pooropssec import alleged_domain
 
 
def test_score_domain():
    '''simple functional red green light test for expected and unexpected quant. measures''' 
    #Unexpected
    assert alleged_domain('go.jpmorgan.com') > 75
    assert alleged_domain('security.coinbase.com') > 75
    assert alleged_domain('xn----paypal.com----yourmom.work') > 55
    #Expected
    assert alleged_domain('www.etrade.com') < 50
