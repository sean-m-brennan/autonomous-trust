/********************
 *  Copyright 2024 TekFive, Inc. and contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *******************/

#define MODULE             
#define __KERNEL__	 
	
#include <linux/module.h>  
#include <linux/config.h>  

#include <linux/netdevice.h> 
	
int radio_sim_open (struct net_device *dev)
{
  printk("radio_sim_open called\n");
  netif_start_queue (dev);
  return 0;
}

int radio_sim_release (struct net_device *dev)
{
  printk ("radio_sim_release called\n");
  netif_stop_queue(dev);
  return 0;
}

static int radio_sim_xmit (struct sk_buff *skb, 
			   struct net_device *dev)
{
  printk ("dummy xmit function called....\n");
  dev_kfree_skb(skb);
  return 0;
}

int radio_sim_init (struct net_device *dev)
{
  dev->open = radio_sim_open;
  dev->stop = radio_sim_release;
  dev->hard_start_xmit = radio_sim_xmit;
  printk ("radio sim device initialized\n");
  return 0;
}

struct net_device radio_sim = {init: radio_sim_init};

int radio_sim_init_module (void)
{
  int result;
  
  strcpy (radio_sim.name, "radio_sim");
  if ((result = register_netdev (&radio_sim))) {
    printk ("radio_sim: Error %d  initializing card radio_sim card",result);
    return result;
  }
  return 0;
}
	
void radio_sim_cleanup (void)
{
  printk ("<0> Cleaning Up the Module\n");
  unregister_netdev (&radio_sim);
  return;
}
	
module_init (radio_sim_init_module);
module_exit (radio_sim_cleanup);
