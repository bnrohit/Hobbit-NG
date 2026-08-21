import random
from collections import defaultdict

class AdaptivePlanner:
    def __init__(self, config, logger):
        ai=config.get("ai",{})
        self.q_table=defaultdict(lambda: defaultdict(float))
        self.epsilon=float(ai.get("exploration_rate",0.1))
        self.learning_rate=float(ai.get("learning_rate",0.1))
        self.discount=float(ai.get("discount_factor",0.9))
        self.logger=logger
    def choose_action(self,state,actions):
        if not actions: return None
        if random.random()<self.epsilon: return random.choice(actions)
        return max(actions,key=lambda a:self.q_table[state][a])
    def update(self,state,action,reward,next_state,next_actions):
        future=max((self.q_table[next_state][a] for a in next_actions),default=0.0)
        target=reward+self.discount*future
        self.q_table[state][action]+=self.learning_rate*(target-self.q_table[state][action])
