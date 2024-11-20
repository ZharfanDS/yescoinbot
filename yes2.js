const fs = require('fs');
const axios = require('axios');
const colors = require('colors');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const crypto = require('crypto');

class YesCoinBot {
    constructor(accountIndex, account, proxy) {
        this.accountIndex = accountIndex;
        this.account = account;
        this.proxy = proxy;
        this.proxyIP = 'Unknown';
        this.token = null;
        this.config = JSON.parse(fs.readFileSync('config.json', 'utf-8'));
		this.timeout = 30000;
    }

    async log(msg, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        const accountPrefix = `[Account ${this.accountIndex + 1}]`;
        const ipPrefix = this.proxyIP ? `[${this.proxyIP}]` : '[Unknown IP]';
        let logMessage = '';
        
        switch(type) {
            case 'success':
                logMessage = `${accountPrefix}${ipPrefix} ${msg}`.green;
                break;
            case 'error':
                logMessage = `${accountPrefix}${ipPrefix} ${msg}`.red;
                break;
            case 'warning':
                logMessage = `${accountPrefix}${ipPrefix} ${msg}`.yellow;
                break;
            default:
                logMessage = `${accountPrefix}${ipPrefix} ${msg}`.blue;
        }
        
        console.log(logMessage);
        await this.randomDelay();
    }

    headers(token) {
        return {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'no-cache',
            'content-type': 'application/json',
            'origin': 'https://www.yescoin.gold',
            'pragma': 'no-cache',
            'priority': 'u=1, i',
            'referer': 'https://www.yescoin.gold/',
            'sec-ch-ua': '"Microsoft Edge";v="125", "Chromium";v="125", "Not.A/Brand";v="24", "Microsoft Edge WebView2";v="125"',
            'sec-Ch-Ua-Mobile': '?1',
            'sec-Ch-Ua-Platform': '"Android"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'token': token,
            'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Mobile Safari/537.36'
        };
    }

    formatLoginPayload(encodedData) {
        const decodedData = decodeURIComponent(encodedData);
        return { code: decodedData };
    }

    async login(encodedData, proxy) {
        const url = 'https://bi.yescoin.gold/user/login';
        const formattedPayload = this.formatLoginPayload(encodedData);
        const headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'origin': 'https://www.yescoin.gold',
            'referer': 'https://www.yescoin.gold/',
            'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Microsoft Edge";v="128", "Microsoft Edge WebView2";v="128"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0'
        };

        try {
            const proxyAgent = new HttpsProxyAgent(proxy);
            const response = await axios.post(url, formattedPayload, { headers, httpsAgent: proxyAgent });
            if (response.data.code === 0) {
                const token = response.data.data.token;
                return token;
            } else {
                throw new Error(`Login failed: ${response.data.message}`);
            }
        } catch (error) {
            throw new Error(`Login failed: ${error.message}`);
        }
    }

    async saveToken(accountIndex, token) {
        let tokens = {};
        if (fs.existsSync('token.json')) {
            tokens = JSON.parse(fs.readFileSync('token.json', 'utf-8'));
        }
        tokens[accountIndex] = token;
        fs.writeFileSync('token.json', JSON.stringify(tokens, null, 2));
    }

    loadToken(accountIndex) {
        if (fs.existsSync('token.json')) {
            const tokens = JSON.parse(fs.readFileSync('token.json', 'utf-8'));
            return tokens[accountIndex];
        }
        return null;
    }

    async getOrRefreshToken(encodedData, proxy) {
        const savedToken = this.loadToken(this.accountIndex);
        if (savedToken) {
            this.token = savedToken;
            return this.token;
        }
        
        this.token = await this.login(encodedData, proxy);
        await this.saveToken(this.accountIndex, this.token);
        return this.token;
    }

    async checkProxyIP(proxy) {
        try {
            const proxyAgent = new HttpsProxyAgent(proxy);
            const response = await axios.get('https://api.ipify.org?format=json', { httpsAgent: proxyAgent });
            if (response.status === 200) {
                return response.data.ip;
            } else {
                throw new Error(`Unable to check proxy IP. Status code: ${response.status}`);
            }
        } catch (error) {
            throw new Error(`Error when checking proxy IP: ${error.message}`);
        }
    }

    async makeRequest(method, url, data = null, token, proxy, extraHeaders = {}) {
        const defaultHeaders = this.headers(token);
        const headers = {
            ...defaultHeaders,
            ...extraHeaders
        };
        const proxyAgent = new HttpsProxyAgent(proxy);
        const config = {
            method,
            url,
            headers,
            httpsAgent: proxyAgent,
            timeout: this.timeout,
        };
        if (data) {
            config.data = data;
        }
        try {
            const response = await axios(config);
            return response.data;
        } catch (error) {
            if (error.code === 'ECONNABORTED') {
                throw new Error(`Request times out after ${this.timeout}ms`);
            }
            throw new Error(`Request failed: ${errorr.message}`);
        }
    }

    async randomDelay() {
        const delay = Math.floor(Math.random() * 1000) + 1000;
        await new Promise(resolve => setTimeout(resolve, delay));
    }

    async collectCoin(token, amount, proxy) {
        const url = 'https://bi.yescoin.gold/game/collectCoin';
        try {
            const response = await this.makeRequest('post', url, amount, token, proxy);
            if (response.code === 0) {
                return response;
            }
            return null;
        } catch (error) {
            return null;
        }
    }

    async getAccountInfo(token, proxy) {
        try {
            const url = 'https://bi.yescoin.gold/account/getAccountInfo';
            const response = await this.makeRequest('get', url, null, token, proxy);
            if (response.code === 0) {
                return response;
            }
            return null;
        } catch (error) {
            return null;
        }
    }

    async getGameInfo(token, proxy) {
        try {
            const url = 'https://bi.yescoin.gold/game/getGameInfo';
            const response = await this.makeRequest('get', url, null, token, proxy);
            if (response.code === 0) {
                return response;
            }
            return null;
        } catch (error) {
            return null;
        }
    }

    async useSpecialBox(token, proxy) {
        const url = 'https://bi.yescoin.gold/game/recoverSpecialBox';
        try {
            const response = await this.makeRequest('post', url, {}, token, proxy);
            if (response.code === 0) {
                await this.log('Activate the chest...', 'success');
                return true;
            } else {
                await this.log('Chest activation failed!', 'error');
                return false;
            }
        } catch (error) {
            return false;
        }
    }

    async getSpecialBoxInfo(token, proxy) {
        try {
            const url = 'https://bi.yescoin.gold/game/getSpecialBoxInfo';
            const response = await this.makeRequest('get', url, null, token, proxy);
            if (response.code === 0) {
                return response;
            }
            return null;
        } catch (error) {
            return null;
        }
    }

    async getuser(token, proxy) {
        try {
            const url = 'https://bi.yescoin.gold/account/getRankingList?index=1&pageSize=1&rankType=1&userLevel=1';
            const response = await this.makeRequest('get', url, null, token, proxy);
            if (response.data.myUserNick) {
                return response.data.myUserNick;
            }
            return "no nickname";
        } catch (error) {
            return "no nickname";
        }
    }

    async collectFromSpecialBox(token, boxType, coinCount, proxy) {
        const url = 'https://bi.yescoin.gold/game/collectSpecialBoxCoin';
        const data = { boxType, coinCount };
        try {
            const response = await this.makeRequest('post', url, data, token, proxy);
            if (response.code === 0) {
                if (response.data.collectStatus) {
                    await this.log(`Open the chest to receive ${response.data.collectAmount} Coins`, 'success');
                    return { success: true, collectedAmount: response.data.collectAmount };
                } else {
                    return { success: true, collectedAmount: 0 };
                }
            } else {
                return { success: false, collectedAmount: 0 };
            }
        } catch (error) {
            return { success: false, collectedAmount: 0 };
        }
    }

    async attemptCollectSpecialBox(token, boxType, initialCoinCount, proxy) {
        let coinCount = initialCoinCount;
        while (coinCount > 0) {
            const result = await this.collectFromSpecialBox(token, boxType, coinCount, proxy);
            if (result.success) {
                return result.collectedAmount;
            }
            coinCount -= 20;
        }
        await this.log('Cannot collect chest!', 'error');
        return 0;
    }

    async getAccountBuildInfo(token, proxy) {
        try {
            const url = 'https://bi.yescoin.gold/build/getAccountBuildInfo';
            const response = await this.makeRequest('get', url, null, token, proxy);
            if (response.code === 0) {
                return response;
            }
            return null;
        } catch (error) {
            return null;
        }
    }

    async getSquadInfo(token, proxy) {
        const url = 'https://bi.yescoin.gold/squad/mySquad';
        try {
            const response = await this.makeRequest('get', url, null, token, proxy);
            if (response.code === 0) {
                return response;
            }
            return null;
        } catch (error) {
            return null;
        }
    }

    async joinSquad(token, squadLink, proxy) {
        const url = 'https://bi.yescoin.gold/squad/joinSquad';
        const data = { squadTgLink: squadLink };
        try {
            const response = await this.makeRequest('post', url, data, token, proxy);
            if (response.code === 0) {
                return response;
            }
            return null;
        } catch (error) {
            return null;
        }
    }

    async recoverCoinPool(token, proxy) {
        const url = 'https://bi.yescoin.gold/game/recoverCoinPool';
        try {
            const response = await this.makeRequest('post', url, {}, token, proxy);
            if (response.code === 0) {
                await this.log('Recovery success!', 'success');
                return true;
            } else {
                await this.log('Recovery failure!', 'error');
                return false;
            }
        } catch (error) {
            return false;
        }
    }

    async getTaskList(token, proxy) {
        const url = 'https://bi.yescoin.gold/task/getCommonTaskList';
        try {
            const response = await this.makeRequest('get', url, null, token, proxy);
            if (response.code === 0) {
                return response.data;
            } else {
                await this.log(`Unable to get task list: ${response.message}`, 'error');
                return null;
            }
        } catch (error) {
            await this.log('Error: ' + error.message, 'error');
            return null;
        }
    }

    async finishTask(token, taskId, proxy) {
        const url = 'https://bi.yescoin.gold/task/finishTask';
        try {
            const response = await this.makeRequest('post', url, taskId, token, proxy);
            if (response.code === 0) {
                await this.log(`Task ${taskId} succeeded | Award: ${response.data.bonusAmount}`, 'success');
                return true;
            } else {
                await this.log(`Task ${taskId} failed: ${response.message}`, 'error');
                return false;
            }
        } catch (error) {
            await this.log(`Error while doing mission: ${error.message}`, 'error');
            return false;
        }
    }

    async processTasks(token, proxy) {
        const tasks = await this.getTaskList(token, proxy);
        if (tasks) {
            for (const task of tasks) {
                if (task.taskStatus === 0) {
                    await this.finishTask(token, task.taskId, proxy);
                }
            }
        }
    }

    async upgradeLevel(token, currentLevel, targetLevel, upgradeType, proxy) {
        const url = 'https://bi.yescoin.gold/build/levelUp';
        const upgradeTypeName = upgradeType === '1' ? 'Multi Value' : 'Fill Rate';

        while (currentLevel < targetLevel) {
            try {
                const response = await this.makeRequest('post', url, upgradeType, token, proxy);
                if (response.code === 0) {
                    currentLevel++;
                    await this.log(`Upgrade ${upgradeTypeName} lên Lv ${currentLevel}`, 'success');
                } else {
                    await this.log(`Upgrade failed: ${response.message}`, 'error');
                    break;
                }
            } catch (error) {
                await this.log('Upgrade error: ' + error.message, 'error');
                break;
            }
        }

        if (currentLevel === targetLevel) {
            await this.log(`${upgradeTypeName} already at the level ${currentLevel}`, 'info');
        }
    }

    generateClaimSign(params, secretKey) {
        const { id, tm, claimType } = params;
        const inputString = id + tm + secretKey + claimType;
        const sign = crypto.createHash('md5').update(inputString).digest('hex');
        return sign;
    }

    async handleSwipeBot(token, proxy) {
        const url = 'https://bi.yescoin.gold/build/getAccountBuildInfo';
        try {
            const accountBuildInfo = await this.makeRequest('get', url, null, token, proxy);
            if (accountBuildInfo.code === 0) {
                const { swipeBotLevel, openSwipeBot } = accountBuildInfo.data;
                if (swipeBotLevel < 1) {
                    const upgradeUrl = 'https://bi.yescoin.gold/build/levelUp';
                    const upgradeResponse = await this.makeRequest('post', upgradeUrl, 4, token, proxy);
                    if (upgradeResponse.code === 0) {
                        await this.log('Successfully purchased SwipeBot', 'success');
                    } else {
                        await this.log('SwipeBot purchase fails', 'error');
                    }
                }
    
                if (swipeBotLevel >= 1 && !openSwipeBot) {
                    const toggleUrl = 'https://bi.yescoin.gold/build/toggleSwipeBotSwitch';
                    const toggleResponse = await this.makeRequest('post', toggleUrl, true, token, proxy);
                    if (toggleResponse.code === 0) {
                        await this.log('Turn on SwipeBot successfully', 'success');
                    } else {
                        await this.log('Turn on SwipeBot failed', 'error');
                    }
                }
    
                if (swipeBotLevel >= 1 && openSwipeBot) {
                    const offlineBonusUrl = 'https://bi.yescoin.gold/game/getOfflineYesPacBonusInfo';
                    const offlineBonusInfo = await this.makeRequest('get', offlineBonusUrl, null, token, proxy);
                    if (offlineBonusInfo.code === 0 && offlineBonusInfo.data.length > 0) {
                        const claimUrl = 'https://bi.yescoin.gold/game/claimOfflineBonus';
                        const tm = Math.floor(Date.now() / 1000);
                        const claimData = {
                            id: offlineBonusInfo.data[0].transactionId,
                            createAt: tm,
                            claimType: 1,
                            destination: ""
                        };
                
                        const signParams = {
                            id: claimData.id,
                            tm: tm,
                            claimType: claimData.claimType
                        };
                
                        const secretKey = '6863b339db454f5bbd42ffb5b5ac9841';
                        const sign = this.generateClaimSign(signParams, secretKey);
                
                        const headers = {
                            'Accept': 'application/json, text/plain, */*',
                            'Accept-Language': 'en-US,en;q=0.9',
                            'Cache-Control': 'no-cache',
                            'Content-Type': 'application/json',
                            'Origin': 'https://www.yescoin.gold',
                            'Pragma': 'no-cache',
                            'Referer': 'https://www.yescoin.gold/',
                            'Sec-Ch-Ua': '"Not.A/Brand";v="8", "Chromium";v="114"',
                            'Sec-Ch-Ua-Mobile': '?0',
                            'Sec-Ch-Ua-Platform': '"Windows"',
                            'Sec-Fetch-Dest': 'empty',
                            'Sec-Fetch-Mode': 'cors',
                            'Sec-Fetch-Site': 'same-site',
                            'Sign': sign,
                            'Tm': tm.toString(),
                            'Token': token,
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                        };                        
                
                        const claimResponse = await this.makeRequest('post', claimUrl, claimData, token, proxy, headers);
                        if (claimResponse.code === 0) {
                            await this.log(`Claim offline bonus successfully, receive it ${claimResponse.data.collectAmount} coins`, 'success');
                        } else {
                            await this.log(`Claim offline bonus failed: ${claimResponse.message}`, 'error');
                        }
                    }
                }                
            } else {
                await this.log('Unable to get SwipeBot information', 'error');
            }
        } catch (error) {
            await this.log(`Lỗi xử lý SwipeBot: ${error.message}`, 'error');
        }
    }

    async performTaskWithTimeout(task, taskName, timeoutMs = this.timeout) {
        return new Promise(async (resolve, reject) => {
            const timeoutId = setTimeout(() => {
                reject(new Error(`${taskName} hết thời gian sau ${timeoutMs}ms`));
            }, timeoutMs);

            try {
                const result = await task();
                clearTimeout(timeoutId);
                resolve(result);
            } catch (error) {
                clearTimeout(timeoutId);
                reject(error);
            }
        });
    }
	
    async main() {
        try {
            try {
                this.proxyIP = await this.performTaskWithTimeout(
                    () => this.checkProxyIP(this.proxy),
                    'Checking proxy IP',
                    10000
                );
                await this.log(`Proxy IP: ${this.proxyIP}`, 'info');
            } catch (error) {
                await this.log(`Error checking IP proxy: ${error.message}`, 'error');
                return;
            }

            try {
                this.token = await this.performTaskWithTimeout(
                    () => this.getOrRefreshToken(this.account, this.proxy),
                    'Getting token',
                    20000
                );
            } catch (error) {
                await this.log(`Cannot get tokens: ${error.message}`, 'error');
                return;
            }

            await this.performTasks();
        } catch (error) {
            await this.log(`It's a mistake: ${error.message}`, 'error');
        } finally {
            if (!isMainThread) {
                parentPort.postMessage('taskComplete');
            }
        }
    }

    async checkAndClaimTaskBonus(token, proxy) {
    const url = 'https://bi.yescoin.gold/task/getFinishTaskBonusInfo';
    try {
        const response = await this.makeRequest('get', url, null, token, proxy);
        if (response.code === 0) {
        const bonusInfo = response.data;
        const claimUrl = 'https://bi.yescoin.gold/task/claimBonus';

        if (bonusInfo.commonTaskBonusStatus === 1) {
            const claimResponse = await this.makeRequest('post', claimUrl, 2, token, proxy);
            if (claimResponse.code === 0) {
            await this.log(`Claim Common Task bonus successfully | award ${claimResponse.data.bonusAmount}`, 'success');
            }
        }

        if (bonusInfo.dailyTaskBonusStatus === 1) {
            const claimResponse = await this.makeRequest('post', claimUrl, 1, token, proxy);
            if (claimResponse.code === 0) {
            await this.log(`Claim Daily Task bonus success | award ${claimResponse.data.bonusAmount}`, 'success');
            }
        }

        if (bonusInfo.commonTaskBonusStatus !== 1 && bonusInfo.dailyTaskBonusStatus !== 1) {
            await this.log('Not eligible for Task bonus', 'info');
            return false;
        }

        return true;
        } else {
        await this.log(`Failed to get bonus task information: ${response.message}`, 'error');
        return false;
        }
    } catch (error) {
        await this.log(`Error when checking and claiming Task bonus: ${error.message}`, 'error');
        return false;
    }
    }

	async performDailyMissions(token, proxy) {
		try {
			const dailyMissionsUrl = 'https://bi.yescoin.gold/mission/getDailyMission';
			const dailyMissionsResponse = await this.makeRequest('get', dailyMissionsUrl, null, token, proxy);

			if (dailyMissionsResponse.code === 0) {
				for (const mission of dailyMissionsResponse.data) {
					if (mission.missionStatus === 0) {
						await new Promise(resolve => setTimeout(resolve, 3000));
						
						const clickUrl = 'https://bi.yescoin.gold/mission/clickDailyMission';
						await this.makeRequest('post', clickUrl, mission.missionId, token, proxy);

						await new Promise(resolve => setTimeout(resolve, 5000));

						const checkUrl = 'https://bi.yescoin.gold/mission/checkDailyMission';
						const checkResponse = await this.makeRequest('post', checkUrl, mission.missionId, token, proxy);

						if (checkResponse.code === 0 && checkResponse.data === true) {
							await new Promise(resolve => setTimeout(resolve, 3000));
							
							const claimUrl = 'https://bi.yescoin.gold/mission/claimReward';
							const claimResponse = await this.makeRequest('post', claimUrl, mission.missionId, token, proxy);

							if (claimResponse.code === 0) {
								const reward = claimResponse.data.reward;
								await this.log(`Mission ${mission.name} completed successfully | Reward: ${reward}`, 'success');
							} else {
								await this.log(`Receive mission rewards ${mission.name} failure: ${claimResponse.message}`, 'error');
							}
						} else {
							await this.log(`Check the mission ${mission.name} failure`, 'error');
						}

						await new Promise(resolve => setTimeout(resolve, 5000));
					}
				}
				return true;
			} else {
				await this.log(`Unable to get daily task list: ${dailyMissionsResponse.message}`, 'error');
				return false;
			}
		} catch (error) {
			await this.log(`Error when performing daily tasks: ${error.message}`, 'error');
			return false;
		}
	}

    generateSign(params, secretKey) {
        const { id, tm, signInType } = params;
        const inputString = id + tm + secretKey + signInType;
        const sign = crypto.createHash('md5').update(inputString).digest('hex');
        return sign;
    }

    async performDailySignIn(token, proxy) {
        try {
            const secretKey = '6863b339db454f5bbd42ffb5b5ac9841';
            const getCurrentTimestamp = () => Math.floor(Date.now() / 1000);
    
            // Lấy danh sách điểm danh
            const signInListUrl = 'https://bi.yescoin.gold/signIn/list';
            const signInListResponse = await this.makeRequest('get', signInListUrl, null, token, proxy);
    
            if (signInListResponse.code === 0) {
                const availableSignIn = signInListResponse.data.find(item => item.status === 1);
    
                if (availableSignIn) {
                    const tm = getCurrentTimestamp();
                    const signInUrl = 'https://bi.yescoin.gold/signIn/claim';
                    const signInData = {
                        id: availableSignIn.id,
                        createAt: tm,
                        signInType: 1,
                        destination: ""
                    };
    
                    const signParams = {
                        id: signInData.id,
                        tm: tm,
                        signInType: signInData.signInType
                    };
    
                    const sign = this.generateSign(signParams, secretKey);
    
                    // Header đầy đủ cho yêu cầu điểm danh
                    const headers = {
                        'Accept': 'application/json, text/plain, */*',
                        'Accept-Language': 'en-US,en;q=0.9',
                        'Cache-Control': 'no-cache',
                        'Content-Type': 'application/json',
                        'Origin': 'https://www.yescoin.gold',
                        'Pragma': 'no-cache',
                        'Referer': 'https://www.yescoin.gold/',
                        'Sec-Ch-Ua': '"Not.A/Brand";v="8", "Chromium";v="114"',
                        'Sec-Ch-Ua-Mobile': '?0',
                        'Sec-Ch-Ua-Platform': '"Windows"',
                        'Sec-Fetch-Dest': 'empty',
                        'Sec-Fetch-Mode': 'cors',
                        'Sec-Fetch-Site': 'same-site',
                        'Sign': sign,
                        'Tm': tm.toString(),
                        'Token': token,
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
                    };
    
                    const signInResponse = await this.makeRequest('post', signInUrl, signInData, token, proxy, headers);
                    if (signInResponse.code === 0) {
                        const reward = signInResponse.data.reward;
                        await this.log(`Successful daily attendance | Award: ${reward}`, 'success');
                        return true;
                    } else {
                        await this.log(`Daily attendance failed: ${JSON.stringify({
                            code: signInResponse.code,
                            message: signInResponse.message,
                            data: signInResponse.data
                        })}`, 'error');
                        return false;
                    }
                } else {
                    await this.log(`Today you have taken attendance`, 'warning');
                    return false;
                }
            } else {
                await this.log(`Unable to get attendance list: ${JSON.stringify({
                    code: signInListResponse.code,
                    message: signInListResponse.message,
                    data: signInListResponse.data
                })}`, 'error');
                return false;
            }
        } catch (error) {
            await this.log(`Error when taking daily attendance: ${error.message}
            Stack: ${error.stack}
            Request details: ${JSON.stringify({
                url: error.config?.url,
                method: error.config?.method,
                headers: error.config?.headers,
                data: error.config?.data
            })}
            Response: ${JSON.stringify({
                status: error.response?.status,
                data: error.response?.data
            })}`, 'error');
            return false;
        }
    }    

    async performTasks() {
        try {
            const nickname = await this.performTaskWithTimeout(
                () => this.getuser(this.token, this.proxy),
                'Getting user info',
                15000
            );
            await this.log(`Tài khoản: ${nickname}`, 'info');

            const squadInfo = await this.performTaskWithTimeout(
                () => this.getSquadInfo(this.token, this.proxy),
                'Getting squad info',
                15000
            );
            if (squadInfo && squadInfo.data.isJoinSquad) {
                const squadTitle = squadInfo.data.squadInfo.squadTitle;
                const squadMembers = squadInfo.data.squadInfo.squadMembers;
                await this.log(`Squad: ${squadTitle} | ${squadMembers} Member`, 'info');
            } else {
                await this.log('Squad: You are not in Squad, join Dan Cay Airdrop.', 'warning');
                const joinResult = await this.performTaskWithTimeout(
                    () => this.joinSquad(this.token, "t.me/AirdropScript6", this.proxy),
                    'Joining squad',
                    20000
                );
                if (joinResult) {
                    await this.log(`Squad: ${nickname} successfully joined Squad!`, 'success');
                } else {
                    await this.log(`Squad: ${nickname} failed to join Squad!`, 'error');
                }
            }

            await this.performTaskWithTimeout(
                () => this.performDailySignIn(this.token, this.proxy),
                'Performing daily sign-in',
                30000
            );

            const balance = await this.performTaskWithTimeout(
                () => this.getAccountInfo(this.token, this.proxy),
                'Getting account info',
                15000
            );
            if (balance === null) {
                await this.log('Balance: Unable to read balance', 'error');
            } else {
                const currentAmount = balance.data.currentAmount.toLocaleString().replace(/,/g, '.');
                await this.log(`Balance: ${currentAmount}`, 'info');
            }

            const gameInfo = await this.performTaskWithTimeout(
                () => this.getAccountBuildInfo(this.token, this.proxy),
                'Getting game info',
                15000
            );
            if (gameInfo === null) {
                await this.log('Could not get game data!', 'error');
            } else {
                const { specialBoxLeftRecoveryCount, coinPoolLeftRecoveryCount, singleCoinValue, singleCoinLevel, coinPoolRecoverySpeed, swipeBotLevel } = gameInfo.data;
                await this.log(`Booster: Chest ${specialBoxLeftRecoveryCount} | Recovery ${coinPoolLeftRecoveryCount}`, 'info');
                await this.log(`Multivalue: ${singleCoinValue} | Coin Limit: ${singleCoinLevel} | Fill Rate: ${coinPoolRecoverySpeed} | Swipe Bot: ${swipeBotLevel}`, 'info');
            }

            await this.performTaskWithTimeout(
                () => this.handleSwipeBot(this.token, this.proxy),
                'Handling SwipeBot',
                30000
            );

            await this.performTaskWithTimeout(
                () => this.performDailyMissions(this.token, this.proxy),
                'Performing daily missions',
                60000
            );
            
            if (this.config.TaskEnable) {
                await this.performTaskWithTimeout(
                    () => this.processTasks(this.token, this.proxy),
                    'Processing tasks',
                    60000
                );
            }

            await this.performTaskWithTimeout(
                () => this.checkAndClaimTaskBonus(this.token, this.proxy),
                'Checking and claiming task bonus',
                30000
            );

            if (this.config.upgradeMultiEnable && gameInfo) {
                await this.performTaskWithTimeout(
                    () => this.upgradeLevel(this.token, gameInfo.data.singleCoinValue, this.config.maxLevel, '1', this.proxy),
                    'Upgrading Multi',
                    60000
                );
            }

            if (this.config.upgradeFillEnable && gameInfo) {
                await this.performTaskWithTimeout(
                    () => this.upgradeLevel(this.token, gameInfo.data.coinPoolRecoverySpeed, this.config.maxLevel, '2', this.proxy),
                    'Upgrading Fill',
                    60000
                );
            }

            const collectInfo = await this.performTaskWithTimeout(
                () => this.getGameInfo(this.token, this.proxy),
                'Getting collect info',
                15000
            );
            if (collectInfo === null) {
                await this.log('Failed to get game data!', 'error');
            } else {
                const { singleCoinValue, coinPoolLeftCount } = collectInfo.data;
                await this.log(`Remaining energy ${coinPoolLeftCount}`, 'info');

                if (coinPoolLeftCount > 0) {
                    const amount = Math.floor(coinPoolLeftCount / singleCoinValue);
                    const collectResult = await this.performTaskWithTimeout(
                        () => this.collectCoin(this.token, amount, this.proxy),
                        'Collecting coins',
                        30000
                    );
                    if (collectResult && collectResult.code === 0) {
                        const collectedAmount = collectResult.data.collectAmount;
                        await this.log(`Tap successfully, receive ${collectedAmount} coins`, 'success');
                    } else {
                        await this.log('Tap failed!', 'error');
                    }
                }
            }

            if (gameInfo && gameInfo.data.specialBoxLeftRecoveryCount > 0) {
                const useSpecialBoxResult = await this.performTaskWithTimeout(
                    () => this.useSpecialBox(this.token, this.proxy),
                    'Using special box',
                    30000
                );
                if (useSpecialBoxResult) {
                    const collectedAmount = await this.performTaskWithTimeout(
                        () => this.attemptCollectSpecialBox(this.token, 2, 240, this.proxy),
                        'Collecting from special box',
                        60000
                    );
                    await this.log(`Collected ${collectedAmount} from special box`, 'success');
                }
            }

            const updatedGameInfo = await this.performTaskWithTimeout(
                () => this.getAccountBuildInfo(this.token, this.proxy),
                'Getting updated game info',
                15000
            );
            if (updatedGameInfo && updatedGameInfo.data.coinPoolLeftRecoveryCount > 0) {
                const recoverResult = await this.performTaskWithTimeout(
                    () => this.recoverCoinPool(this.token, this.proxy),
                    'Recovering coin pool',
                    30000
                );
                if (recoverResult) {
                    const updatedCollectInfo = await this.performTaskWithTimeout(
                        () => this.getGameInfo(this.token, this.proxy),
                        'Getting updated collect info',
                        15000
                    );
                    if (updatedCollectInfo) {
                        const { coinPoolLeftCount, singleCoinValue } = updatedCollectInfo.data;
                        if (coinPoolLeftCount > 0) {
                            const amount = Math.floor(coinPoolLeftCount / singleCoinValue);
                            const collectResult = await this.performTaskWithTimeout(
                                () => this.collectCoin(this.token, amount, this.proxy),
                                'Collecting coins after recovery',
                                30000
                            );
                            if (collectResult && collectResult.code === 0) {
                                const collectedAmount = collectResult.data.collectAmount;
                                await this.log(`Tap successfully after recovery, receive ${collectedAmount} coins`, 'success');
                            } else {
                                await this.log('Tap failed after recovery!', 'error');
                            }
                        }
                    }
                }
            }

            const freeChestCollectedAmount = await this.performTaskWithTimeout(
                () => this.attemptCollectSpecialBox(this.token, 1, 200, this.proxy),
                'Collecting from free chest',
                30000
            );
            await this.log(`Collected ${freeChestCollectedAmount} from free chest`, 'success');

        } catch (error) {
            await this.log(`Error in performTasks: ${error.message}`, 'error');
        }
    }
}

if (isMainThread) {
    const accounts = fs.readFileSync('data.txt', 'utf-8').replace(/\r/g, '').split('\n').filter(Boolean);
    const proxies = fs.readFileSync('proxy.txt', 'utf-8').replace(/\r/g, '').split('\n').filter(Boolean);
    const config = JSON.parse(fs.readFileSync('config.json', 'utf-8'));

    const numThreads = Math.min(config.maxThreads || 10, accounts.length);
    let activeWorkers = 0;

    async function processCycle() {
    console.log(`
    ░▀▀█░█▀█░▀█▀░█▀█
    ░▄▀░░█▀█░░█░░█░█
    ░▀▀▀░▀░▀░▀▀▀░▀░▀
    ╔══════════════════════════════════╗
    ║                                  ║
    ║  ZAIN ARAIN                      ║
    ║  AUTO SCRIPT MASTER              ║
    ║                                  ║
    ║  JOIN TELEGRAM CHANNEL NOW!      ║
    ║  https://t.me/AirdropScript6     ║
    ║  @AirdropScript6 - OFFICIAL      ║
    ║  CHANNEL                         ║
    ║                                  ║
    ║  FAST - RELIABLE - SECURE        ║
    ║  SCRIPTS EXPERT                  ║
    ║                                  ║
    ╚══════════════════════════════════╝
    `.cyan);

    console.log('If you use it, do not be afraid, If you are afraid, do not use it...'.magenta);
    let accountQueue = [...accounts];

    function startWorker() {
        if (accountQueue.length === 0) {
            if (activeWorkers === 0) {
                console.log('Complete all accounts, take a break.'.green);
                    setTimeout(processCycle, 60000);
                }
                return;
            }

            const accountIndex = accounts.length - accountQueue.length;
            const account = accountQueue.shift();
            const proxy = proxies[accountIndex % proxies.length];

            activeWorkers++;

            const worker = new Worker(__filename, {
                workerData: {
                    accountIndex: accountIndex,
                    account: account,
                    proxy: proxy
                }
            });

            worker.on('message', (message) => {
                if (message === 'taskComplete') {
                    worker.terminate();
                }
            });

            worker.on('error', (error) => {
                console.error(`Worker error: ${error}`.red);
                activeWorkers--;
                startWorker();
            });

            worker.on('exit', (code) => {
                if (code !== 0) {
                    console.error(`Stream stopped with code ${code}`.red);
                }
                activeWorkers--;
                startWorker();
            });
        }

        for (let i = 0; i < numThreads; i++) {
            startWorker();
        }
    }
    processCycle();

} else {
    const bot = new YesCoinBot(workerData.accountIndex, workerData.account, workerData.proxy);
    bot.main().catch(console.error);
}